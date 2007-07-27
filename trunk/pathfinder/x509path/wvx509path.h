/* -*- Mode: C++ -*-                                 
 * X.509 certificate path management classes.        
 * 
 * Copyright (C) 2007, Carillon Information Security Inc.   
 *  
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.   
 */ 
      

#ifndef __WVX509PATH_H
#define __WVX509PATH_H
#include <boost/shared_ptr.hpp>
#include <list>
#include <map>
#include <wvcrl.h>
#include <wvlinklist.h>
#include <wvx509.h>
#include "wvx509store.h"


#define WVX509_SKIP_CRL_CHECK 0x2
#define WVX509_IGNORE_MISSING_CRLS 0x4
#define WVX509_SKIP_POLICY_CHECK 0x8
#define WVX509_INITIAL_EXPLICIT_POLICY 0x10
#define WVX509_INITIAL_POLICY_MAPPING_INHIBIT 0x20


class WvX509Path
{
  public:
    WvX509Path();
    virtual ~WvX509Path();
    typedef std::list< boost::shared_ptr<WvX509> > WvX509List;
    bool validate(boost::shared_ptr<WvX509Store> &trusted_store, 
                  boost::shared_ptr<WvX509Store> &intermediate_store,
                  WvStringList &initial_policy_set, 
                  uint32_t flags,
                  WvX509List &extra_certs_to_be_validated,
                  WvError &err);
    WvString get_end_entity_ski();
    void prepend_cert(boost::shared_ptr<WvX509> &cert);
    void append_cert(boost::shared_ptr<WvX509> &cert);
    void add_crl(WvStringParm ski, boost::shared_ptr<WvCRL> &crl);

  private:
    // used when validation fails: logs an error message AND sets the error
    void validate_failed(WvStringParm errstring, WvError &err);

    // a list of X509 certificates, to be validated
    WvX509List x509_list;

    // CRL map: map of associations between CRLs and SKIs
    // of the ca certificates they apply to (which need not be the
    // CRL signer or issuer!)
    typedef std::multimap< std::string, boost::shared_ptr<WvCRL> > CRLMap;
    CRLMap crl_map;
    typedef std::pair< std::string, boost::shared_ptr<WvCRL> > CRLPair;

    WvLog log;
};

#endif
