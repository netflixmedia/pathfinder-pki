/*
 * libpathfinder-nss.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#include "libpathfinder-nss.h"
#include "libpathfinder.h"

extern "C" {

SECStatus nss_verify_cb(void *arg, PRFileDesc *socket, PRBool checksig, 
                        PRBool isServer)
{    
    if (!socket || !arg) 
    {
        fprintf(stderr, "Error in nss_verify_cb: No socket.\n");
        return SECFailure;
    }

    CERTCertificate * cert = SSL_PeerCertificate(socket);
    if (!cert)
    {
        fprintf(stderr, "Error in nss_verify_cb: No certificate "
                "corresponding to socket.\n");
        return SECFailure;
    }

    char * certdata_str = CERT_Hexify(&(cert->derCert), 0);
    const char *policy = "2.5.29.32.0"; // anyPolicy
    char *errmsg;
    int validated = pathfinder_dbus_verify(certdata_str, policy, 0, 0, 
                                           &errmsg);
    free(errmsg);
    PORT_Free(certdata_str);

    if (validated)
        return SECSuccess;

    return SECFailure;
}

}
