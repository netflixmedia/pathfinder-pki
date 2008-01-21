/*
 * libpathfinder.h
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#ifndef __LIBPATHFINDER_H
#define __LIBPATHFINDER_H

#ifdef __cplusplus
extern "C" {
#endif
    int pathfinder_dbus_verify(const char *certhex, const char *policy, 
                               const int initial_explicit_policy, 
                               const int initial_policy_mapping_inhibit,
                               char **errmsg);
#ifdef __cplusplus
}
#endif

#endif // __LIBPATHFINDER_H
