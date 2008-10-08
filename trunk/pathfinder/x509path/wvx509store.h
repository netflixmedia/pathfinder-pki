/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007, Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */ 
/* -*- Mode: C++ -*-
 * X.509 certificate store management classes.
 */ 
#ifndef __WVX509STORE_H
#define __WVX509STORE_H

#include <wvx509.h>

#include <boost/shared_ptr.hpp>
#include <map>
#include <list>


typedef std::list< boost::shared_ptr<WvX509> > WvX509List;


class WvX509Store : public WvErrorBase
{
  public:
    WvX509Store();
    virtual ~WvX509Store();

    /// Returns true if a certificate matches a certificate in the store (by
    // checking for matching SKI's and self-signature).
    bool exists(WvX509 *cert);
    // Returns true if an SKI matches a certificate in the store
    bool exists(WvStringParm ski);
    // Retuns the cert in the store corresponding to SKI (null if none exists)
    // if there is more than one cert corresponding to the SKI, there are no
    // guarantees which one you will get...
    boost::shared_ptr<WvX509> get(WvStringParm ski);
    // Returns the certificates in the store corresponding to SKI
    void get(WvStringParm ski, WvX509List &certlist);
    // Returns all certificates that match the subject, but not the ski of
    // a certificate, and which are not self-signed.
    void get_cross_certs(boost::shared_ptr<WvX509> &cert, 
                         WvX509List &certlist);

    void load(WvStringParm _dir);
    void add_file(WvStringParm _fname);
    void add_cert(boost::shared_ptr<WvX509> &_cert);
    void add_pkcs7(WvStringParm _fname);
    int count();
    
  private:
    typedef std::multimap< std::string, boost::shared_ptr<WvX509> > CertMap;
    typedef std::pair< std::string, boost::shared_ptr<WvX509> > CertPair;
    CertMap certmap;
    
    WvLog log;
};

#endif
