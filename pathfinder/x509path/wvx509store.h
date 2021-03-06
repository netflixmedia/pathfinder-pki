/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
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
#include <stdint.h>


typedef std::list< boost::shared_ptr<WvX509> > WvX509List;


class WvX509Store : public WvErrorBase
{
public:
    WvX509Store();
    virtual ~WvX509Store();

    void set_storedir(WvStringParm _dir);

    /// Returns true if a certificate matches a certificate in the store (by
    // checking for matching SKI's (or subjects, if no SKI) and 
    // self-signature).
    bool exists(WvX509 *cert);
    // Returns true if key matches a certificate in the store
    bool exists(WvStringParm key);
    // Retuns the cert in the store corresponding to key (null if none exists)
    // if there is more than one cert corresponding to the key, there are no
    // guarantees which one you will get...
    boost::shared_ptr<WvX509> get(WvStringParm key);
    // Returns the certificates in the store corresponding to key
    void get(WvStringParm key, WvX509List &certlist);
    // Returns all certificates that match the subject, but not the ski of
    // a certificate, and which are not self-signed.
    void get_cross_certs(boost::shared_ptr<WvX509> &cert, 
                         WvX509List &certlist);

    void load(WvStringParm _dir);
    void add_file(WvStringParm _fname);
    void add_cert(boost::shared_ptr<WvX509> &_cert);
    void add_pkcs7(WvStringParm _fname);
    int count();
    void remove(WvStringParm serial, WvStringParm subject);
    
private:
    WvString storedir;
    typedef std::multimap< std::string, boost::shared_ptr<WvX509> > CertMap;
    typedef std::pair< std::string, boost::shared_ptr<WvX509> > CertPair;
    CertMap certmap;
    
    WvLog log;
};

#endif
