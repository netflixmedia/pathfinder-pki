/*
 * libpathfinder-nss.h
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#ifndef __LIBPATHFINDER_NSS_H
#define __LIBPATHFINDER_NSS_H
#include <nss.h>
#include <prio.h>
#include <secitem.h>
#include <ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

SECStatus nss_verify_cb(void *arg, PRFileDesc *socket, PRBool checksig, 
                        PRBool isServer);
#ifdef __cplusplus
}
#endif
#endif // __LIBPATHFINDER_NSS_H
