/*
 * nsstest.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 * Portions copyright (C) The Mozilla Foundation
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nspr.h>
#include <nss.h>
#include <pk11func.h>
#include <plgetopt.h>

#include "libpathfinder-nss.h"

#define RD_BUF_SIZE (60 * 1024)

char *certnick = NULL;
char *hostname = NULL;
char *password = NULL;
unsigned short port = 0;


/**************************************************************************
** 
** SSL callback routines.
**
**************************************************************************/

char * get_passwd_cb(PK11SlotInfo *info, PRBool retry, void *arg)
{
    char * passwd = NULL;

    if ( (!retry) && arg )
        passwd = PORT_Strdup((char *)arg);

    return passwd;
}

SECStatus get_client_authdata_cb(void *arg, PRFileDesc *socket,
                                 struct CERTDistNamesStr *caNames,
                                 struct CERTCertificateStr **retcert,
                                 struct SECKEYPrivateKeyStr **retkey) 
{
    CERTCertificate *  cert;
    SECKEYPrivateKey * privkey;
    char * chosen_nick = (char *)arg;
    void * proto_win = NULL;

    proto_win = SSL_RevealPinArg(socket);

    if (!chosen_nick)
    {
        fprintf(stderr, "No chosen nickname: Can't get client certificate "
                "info.\n");
        return SECFailure;
    }

    cert = PK11_FindCertFromNickname(chosen_nick, proto_win);
    if (!cert)
    {
        fprintf(stderr, "No certificate corresponding to nickname.\n");
        return SECFailure;
    }
    privkey = PK11_FindKeyByAnyCert(cert, proto_win);
    if (!privkey)
    {
        fprintf(stderr, "No private key corresponding to certificate.\n");
        return SECFailure;
    }

    *retcert = cert;
    *retkey  = privkey;

    return SECSuccess;
}


/**************************************************************************
** 
** Error and information routines.
**
**************************************************************************/

void err_warn(const char *function)
{
    PRErrorCode  errorNumber = PR_GetError();
    
    fprintf(stderr, "Error in function %s: %d\n", function, errorNumber);
}


void err_exit(const char *function)
{
    err_warn(function);
    /* Exit gracefully. */
    /* ignoring return value of NSS_Shutdown as code exits with 1*/
    (void) NSS_Shutdown();
    PR_Cleanup();
    exit(1);
}


static void usage(const char *progname)
{
    fprintf(stderr, 
            "Usage: %s [-n rsa_nickname] [-p port] [-d dbdir]\n"
            "          [-w dbpasswd] hostname\n",
            progname);
    exit(1);
}

/**************************************************************************
** 
** Connection management routines.
**
**************************************************************************/

PRFileDesc * setup_ssl(PRNetAddr *addr)
{
    PRFileDesc *tcpsock;
    PRFileDesc *sslsock;
    PRSocketOptionData socketOption;
    PRStatus prstatus;
    SECStatus secstatus;

    tcpsock = PR_NewTCPSocket();
    if (tcpsock == NULL) 
        err_warn("PR_NewTCPSocket");

    /* Make the socket blocking. */
    socketOption.option = PR_SockOpt_Nonblocking;
    socketOption.value.non_blocking = PR_FALSE;

    prstatus = PR_SetSocketOption(tcpsock, &socketOption);
    if (prstatus != PR_SUCCESS) 
    {
        err_warn("PR_SetSocketOption");
        goto loser;
    } 

    /* Import the socket into the SSL layer. */
    sslsock = SSL_ImportFD(NULL, tcpsock);
    if (!sslsock) 
    {
        err_warn("SSL_ImportFD");
        goto loser;
    }

    /* Set configuration options. */
    secstatus = SSL_OptionSet(sslsock, SSL_SECURITY, PR_TRUE);
    if (secstatus != SECSuccess) 
    {
        err_warn("SSL_OptionSet:SSL_SECURITY");
        goto loser;
    }

    secstatus = SSL_OptionSet(sslsock, SSL_HANDSHAKE_AS_CLIENT, PR_TRUE);
    if (secstatus != SECSuccess) 
    {
        err_warn("SSL_OptionSet:SSL_HANDSHAKE_AS_CLIENT");
        goto loser;
    }

    /* Set SSL callback routines. */
    secstatus = SSL_GetClientAuthDataHook(
        sslsock, (SSLGetClientAuthData)get_client_authdata_cb,
        (void *)certnick);
    if (secstatus != SECSuccess) 
    {
        err_warn("SSL_GetClientAuthDataHook");
        goto loser;
    }

    secstatus = SSL_AuthCertificateHook(sslsock,
                                        (SSLAuthCertificate)nss_verify_cb,
                                        (void *)CERT_GetDefaultCertDB());
    if (secstatus != SECSuccess) 
    {
        err_warn("SSL_AuthCertificateHook");
        goto loser;
    }

    return sslsock;

  loser:
    PR_Close(tcpsock);
    return NULL;
}


const char requestString[] = {"GET /testfile HTTP/1.0\r\n\r\n" };

SECStatus handle_connection(PRFileDesc *sslsock, int connection)
{
	int numread = 0;
	PRInt32 numbytes;
	char *buf;

	buf = (char *)PORT_Alloc(RD_BUF_SIZE);
        if (!buf) 
            err_exit("PORT_Alloc");

	/* compose the http request here. */
	numbytes = PR_Write(sslsock, requestString, strlen(requestString));
	if (numbytes <= 0) 
        {
            fprintf(stderr, "Error writing http request.\n");
            PR_Free(buf);
            buf = NULL;
            return SECFailure;
	}

	/* read until EOF */
	while (PR_TRUE) 
        {
            numbytes = PR_Read(sslsock, buf, RD_BUF_SIZE);
            if (numbytes == 0) {
                break;	/* EOF */
            }
            if (numbytes < 0) {
                fprintf(stderr, "Error reading bytes from socket.\n");
                break;
            }
            numread += numbytes;
            fprintf(stderr, "***** Connection %d read %d bytes (%d total).\n", 
                    connection, numbytes, numread);
            buf[numbytes] = '\0';
            fprintf(stderr, "************\n%s\n************\n", buf);
	}
        
	PR_Free(buf);
	buf = NULL;
        
	/* Caller closes the socket. */

	fprintf(stderr, "***** Connection %d read %d bytes total.\n", 
	        connection, numread);

	return SECSuccess;
}


SECStatus do_connect(void *a, int connection)
{
	PRNetAddr  *addr = (PRNetAddr *)a;
	PRFileDesc *sslsock;
	PRHostEnt   host_entry;
	char        buffer[PR_NETDB_BUF_SIZE];
	PRStatus    prstatus;
	PRIntn      hostenum;
	SECStatus   secstatus;

	/* Set up SSL secure socket. */
	sslsock = setup_ssl(addr);
	if (sslsock == NULL) 
        {
		err_warn("setup_ssl");
		return SECFailure;
	}

	secstatus = SSL_SetPKCS11PinArg(sslsock, password);
	if (secstatus != SECSuccess) 
        {
		err_warn("SSL_SetPKCS11PinArg");
		return secstatus;
	}

	secstatus = SSL_SetURL(sslsock, hostname);
	if (secstatus != SECSuccess) 
        {
		err_warn("SSL_SetURL");
		return secstatus;
	}

	/* Prepare and setup network connection. */
	prstatus = PR_GetHostByName(hostname, buffer, sizeof(buffer), &host_entry);
	if (prstatus != PR_SUCCESS) 
        {
		err_warn("PR_GetHostByName");
		return SECFailure;
	}

	hostenum = PR_EnumerateHostEnt(0, &host_entry, port, addr);
	if (hostenum == -1) 
        {
		err_warn("PR_EnumerateHostEnt");
		return SECFailure;
	}

	prstatus = PR_Connect(sslsock, addr, PR_INTERVAL_NO_TIMEOUT);
	if (prstatus != PR_SUCCESS) 
        {
		err_warn("PR_Connect");
		return SECFailure;
	}
	/* Established SSL connection, ready to send data. */
	secstatus = SSL_ResetHandshake(sslsock, /* asServer */ PR_FALSE);
	if (secstatus != SECSuccess) 
        {
            err_warn("SSL_ResetHandshake");
            prstatus = PR_Close(sslsock);
            if (prstatus != PR_SUCCESS) 
                err_warn("PR_Close");
            return secstatus;
	}

	secstatus = handle_connection(sslsock, connection);
	if (secstatus != SECSuccess) 
        {
            err_warn("handle_connection");
            return secstatus;
	}

	PR_Close(sslsock);
	return SECSuccess;
}


void client_main(unsigned short port, const char * hostname)
{
    PRStatus    prstatus;
    PRInt32     rv;
    PRNetAddr	addr;
    PRHostEnt   host_entry;
    char        buf[256];

    /* Setup network connection. */
    prstatus = PR_GetHostByName(hostname, buf, 256, &host_entry);
    if (prstatus != PR_SUCCESS) 
        err_exit("PR_GetHostByName");
    

    rv = PR_EnumerateHostEnt(0, &host_entry, port, &addr);
    if (rv < 0) 
        err_exit("PR_EnumerateHostEnt");
    
    do_connect(&addr, 1);
}

/**************************************************************************
** 
** Main program.
**
**************************************************************************/

int main(int argc, char *argv[])
{
    const char * certdir = ".";
    SECStatus secstatus;
    PLOptState * optstate;
    PLOptStatus optstatus;

    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    hostname = NULL;
    optstate = PL_CreateOptState(argc, argv, "C:c:d:n:p:w:");
    while ((optstatus = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
        switch(optstate->option) {
        case 'd' : certdir = PL_strdup(optstate->value);      break;
        case 'n' : certnick = PL_strdup(optstate->value); break;
        case 'p' : port = PORT_Atoi(optstate->value);         break;
        case 'w' : password = PL_strdup(optstate->value);     break;
        case '\0': hostname = PL_strdup(optstate->value);     break;
        default  : usage(argv[1]);
        }
    }

    if (port == 0 || hostname == NULL)
        usage(argv[1]);

    if (certdir == NULL) 
        certdir = PR_smprintf("%s/.netscape", getenv("HOME"));

    PK11_SetPasswordFunc(get_passwd_cb);

    secstatus = NSS_Init(certdir);
    if (secstatus != SECSuccess) {
        fprintf(stderr, "Error initializing NSS.\n");
        return 1;
    }

    NSS_SetDomesticPolicy();

    client_main(port, hostname);

    if (NSS_Shutdown() != SECSuccess) {
        exit(1);
    }
    PR_Cleanup();
    return 0;
}

