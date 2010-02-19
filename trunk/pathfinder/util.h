/*
 * util.h
 *
 * Copyright (C) 2008-2009 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */
#ifndef __UTIL_H
#define __UTIL_H
#include <wvbuf.h>
#include <wvstring.h>
#include <wvx509.h>
#include <boost/shared_ptr.hpp>

// various little utility functions which are useful for pathfinder

class WvUrl;

WvX509::DumpMode guess_encoding(WvBuf &buf);
WvX509::DumpMode guess_encoding(WvStringParm fname);

bool is_md(boost::shared_ptr<WvX509> &x509);

// bool is_valid_host(WvStringParm hostname_or_ip);

WvUrl rewrite_url(WvUrl url, WvStringParm hostname_or_ip);

#endif // __UTIL_H
