/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007, Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for 
 * details.
 */ 
/* -*- Mode: C++ -*-
 * CRL store management classes.
 */ 

#ifndef __WVCRLSTORE_H
#define __WVCRLSTORE_H

#include <wvbuf.h>
#include <wvcrl.h>
#include <boost/shared_ptr.hpp>


class WvCRLStore
{
  public:
    WvCRLStore(WvStringParm _dir);
    bool exists(WvStringParm crldp);
    boost::shared_ptr<WvCRL> get(WvStringParm crldp);
    void add(WvStringParm uri, WvBuf &buf);
    
  private:
    WvString dir;
    WvLog log;
};

#endif
