/*
 * libpathfinder-openssl.h
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#ifndef __LIBPATHFINDER_OPENSSL_H
#define __LIBPATHFINDER_OPENSSL_H
#include <openssl/ssl.h>
extern "C" {
int openssl_verify_cb(X509_STORE_CTX *ctx, void *arg);
}
#endif // __LIBPATHFINDER_OPENSSL_H
