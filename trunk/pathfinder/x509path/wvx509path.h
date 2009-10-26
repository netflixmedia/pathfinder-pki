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
#include <map>
#include <stdint.h>
#include <wvcrl.h>
#include <wvocsp.h>
#include <wvx509.h>
#include "wvx509store.h"


#define WVX509_SKIP_REVOCATION_CHECK 0x2
#define WVX509_IGNORE_MISSING_CRLS 0x4
#define WVX509_SKIP_POLICY_CHECK 0x8
#define WVX509_INITIAL_EXPLICIT_POLICY 0x10
#define WVX509_INITIAL_POLICY_MAPPING_INHIBIT 0x20


class WvX509Path
{
  public:
    WvX509Path();
    virtual ~WvX509Path();
    bool validate(boost::shared_ptr<WvX509Store> &trusted_store, 
                  boost::shared_ptr<WvX509Store> &intermediate_store,
                  WvStringList &initial_policy_set, 
                  uint32_t flags,
                  WvX509List &extra_certs_to_be_validated,
                  WvError &err);
    WvString get_end_entity_ski();
    WvString subject_at_front() const
        { return x509_list.front()->get_subject(); }
    void pop_front()
        { x509_list.pop_front(); }
    void prepend_cert(boost::shared_ptr<WvX509> &cert);
    void append_cert(boost::shared_ptr<WvX509> &cert);
    void add_crl(WvStringParm subject, boost::shared_ptr<WvCRL> &crl);
    void add_ocsp_resp(WvStringParm subject,
                       boost::shared_ptr<WvOCSPResp> &ocsp);
    WvX509List::iterator begin() { return x509_list.begin(); }
    WvX509List::iterator end() { return x509_list.end(); }
    size_t pathsize() const
        { return x509_list.size(); }

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

    // OCSPResp map: same as CRL map, but for OCSP responses
    typedef std::multimap< std::string, boost::shared_ptr<WvOCSPResp> > OCSPRespMap;
    OCSPRespMap ocsp_map;
    typedef std::pair< std::string, boost::shared_ptr<WvOCSPResp> > OCSPRespPair;

    WvLog log;
};

#endif
