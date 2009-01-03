/*
 * openssltest.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <assert.h>

#ifdef APPLE
#include <strings.h>
#endif

#include "libpathfinder-openssl.h"


struct CertPair
{
    X509 *x509;
    rsa_st *rsa;
};


static void read_pkcs12(const char *fname, const char *passwd, 
                        CertPair &certpair)
{
    certpair.x509 = NULL;
    certpair.rsa = NULL;

    FILE *fp = fopen(fname, "r");
    if (!fp)
    {
        fprintf(stderr, "Couldn't open file %s.\n", fname);
        exit(1);
    }

    PKCS12 *pkg = d2i_PKCS12_fp(fp, NULL);
    if (!pkg)
    {
        fprintf(stderr, "File %s does not seem to be a valid pkcs12 "
                "bundle.\n", fname);
        exit(1);
    }

    EVP_PKEY *pk = NULL;
    PKCS12_parse(pkg, passwd, &pk, &(certpair.x509), NULL);
    if (!pk || !certpair.x509)
    {
        fprintf(stderr, "Could not retrieve certificate + rsa key pair from "
                "pkcs12 file %s.\n", fname);
        exit(1);
    }
    certpair.rsa = EVP_PKEY_get1_RSA(pk);
    assert(certpair.rsa);
    EVP_PKEY_free(pk);
    fclose(fp);
}


static void parse_addr(const char *host, uint32_t &addr, unsigned short &port)
{
    const char *portstr = strchr(host, ':');
    assert(portstr);
    port = strtol(portstr+1, NULL, 10);

    // shamelessly stolen from wvaddr in wvstreams
    const char *iptr, *nptr;
    unsigned char ip[4];

    nptr = host;
    for (int count=0; count < 4; count++)
    {
	iptr = nptr;
	nptr = strchr(iptr, '.');
        assert(nptr || count==3);
	if (nptr)
            nptr++;
	ip[count] = strtol(iptr, NULL, 10);
    }
    
    addr = *(uint32_t *)ip;
}


int main(int argc, char *argv[])
{    
    if (argc < 3)
    {
        printf("USAGE: %s HOST:PORT CERTPAIR.p12\n", argv[0]);
        return 1;
    }

    uint32_t addr;
    unsigned short port;
    parse_addr(argv[1], addr, port);

    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    
    CertPair certpair;
    read_pkcs12(argv[2], "123", certpair);

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx)
    {
        fprintf(stderr, "Could not create SSL context.\n");
        exit(1);
    }
    if (SSL_CTX_use_certificate(ctx, certpair.x509) <= 0 ||
        SSL_CTX_use_RSAPrivateKey(ctx, certpair.rsa) <= 0)
    {
        fprintf(stderr, "Could not set up SSL context.\n");
        exit(1);
    }
        
    SSL *ssl = SSL_new(ctx);    
    SSL_CTX_set_cert_verify_callback(ctx, &openssl_verify_cb, NULL); 
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL); 

    struct sockaddr_in them;
    memset((char *)&them,0,sizeof(them));
    them.sin_family=AF_INET;
    them.sin_port=htons((unsigned short)port);
    them.sin_addr.s_addr=addr;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (!fd)
    {
        fprintf(stderr, "Error setting up socket.\n");
        exit(1);
    }
    if (connect(fd, (struct sockaddr *)&them, sizeof(them)) != 0)
    {
        fprintf(stderr, "Error initializing connection on socket.\n");
        exit(1);
    }

    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) < 0)
    {
        fprintf(stderr, "Error initializing SSL connection on socket.\n");
        exit(1);
    }

    // oh god this is hacky
    const char *data = "GET /testfile HTTP/1.0\r\n\r\n";
    SSL_write(ssl, data, strlen(data));
    
    while (1)
    {
        char buf[80];
        int numread;

        numread = SSL_read(ssl, buf, 79);
        if (numread > 0)
        {
            buf[numread] = '\0';
            fprintf(stderr, "SSL Read: %s\n", buf);
        }
    }
}

