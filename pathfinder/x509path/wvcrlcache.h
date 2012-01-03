/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for 
 * details.
 */ 
/* -*- Mode: C++ -*-
 * CRL store management classes.
 */ 

#ifndef __WVCRLSTORE_H
#define __WVCRLSTORE_H

#include <boost/shared_ptr.hpp>
#include <map>
#include <wvbuf.h>
#include <wvcrl.h>


class WvCRLCache
{
  public:
    WvCRLCache(WvStringParm _dir);
    boost::shared_ptr<WvCRL> get_url(WvStringParm crldp);
    boost::shared_ptr<WvCRL> get_file(WvStringParm fname);
    
    void add(WvStringParm uri, WvBuf &buf);
    
  private:
    boost::shared_ptr<WvCRL> get(WvStringParm rawpath);

    struct CRLCacheEntry
    {
        CRLCacheEntry(time_t _mtime, boost::shared_ptr<WvCRL> _crl)
        {
            mtime = _mtime;
            crl = _crl;
        } 
        CRLCacheEntry()
        {
            mtime = 0;
        }
        time_t mtime;
        boost::shared_ptr<WvCRL> crl;
    };
    typedef std::map< std::string, CRLCacheEntry > CRLMap;
    CRLMap crlmap;

    WvString dir;
    WvLog log;
};

#endif
