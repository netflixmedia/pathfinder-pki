/*
 * pathvalidator.h
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#ifndef __PATHVALIDATOR_H
#define __PATHVALIDATOR_H
#include "pathfinder.h"


class PathValidator
{
  public:
    typedef wv::function<void(boost::shared_ptr<WvX509> &, bool, 
                              WvError)> ValidatedCb;
    PathValidator(boost::shared_ptr<WvX509> &_cert,
                  WvStringParm _initial_policy_set_tcl, 
                  uint32_t _validation_flags,
                  boost::shared_ptr<WvX509Store> &_trusted_store,
                  boost::shared_ptr<WvX509Store> &_intermediate_store,
                  boost::shared_ptr<WvX509Store> &_fetched_store,
                  boost::shared_ptr<WvCRLCache> &_crlcache,
                  UniConf &_cfg, 
                  ValidatedCb _cb);
    
    void validate(bool check_ocsp = true);

  private:
    void path_found_cb(boost::shared_ptr<WvX509Path> &path, WvError err,
                       boost::shared_ptr<WvX509> &cert);

    boost::shared_ptr<WvX509> cert_to_be_validated;
    WvX509List certs_to_be_validated;
    WvStringList initial_policy_set;
    uint32_t validation_flags;

    // keep a list of pathfinder objects we create, for reference counting
    // purposes
    std::list<boost::shared_ptr<PathFinder> > pathfinder_list;

    boost::shared_ptr<WvX509Store> trusted_store;
    boost::shared_ptr<WvX509Store> intermediate_store;
    boost::shared_ptr<WvX509Store> fetched_store;
    boost::shared_ptr<WvCRLCache> crlcache;

    UniConf cfg;
    ValidatedCb validated_cb;

    WvLog log;
};

#endif // __PATHVALIDATOR_H
