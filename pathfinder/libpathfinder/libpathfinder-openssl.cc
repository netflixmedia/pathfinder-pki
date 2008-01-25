/*
 * libpathfinder-openssl.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#include "libpathfinder-openssl.h"
#include "libpathfinder.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

extern "C" {

static const char* hex = "0123456789ABCDEF";

int openssl_verify_cb(X509_STORE_CTX *ctx, void *arg)
{
    size_t size = i2d_X509(ctx->cert, NULL);
    unsigned char *keybuf, *iend;
    iend = keybuf = new unsigned char[size];
    i2d_X509(ctx->cert, &iend);
    char *certdata_str = new char[(size * 2 + 1)];
    unsigned char *cp = keybuf;
    char *certdata_str_i = certdata_str;
    while (cp < iend) 
    {
	unsigned char ch = *cp++;
	*certdata_str_i++ = hex[(ch >> 4) & 0xf];
	*certdata_str_i++ = hex[ch & 0xf];
    }
    *certdata_str_i = 0;
    delete [] keybuf;

    const char *policy = "2.5.29.32.0"; // anyPolicy
    char *errmsg;
    int validated = pathfinder_dbus_verify(certdata_str, policy, 0, 0, 
                                           &errmsg);
    free(errmsg);

    delete[] certdata_str;

    return validated;
}

}
