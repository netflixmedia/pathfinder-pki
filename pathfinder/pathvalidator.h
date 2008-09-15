/*
 * pathvalidator.h
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
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
                  UniConf &_cfg, 
                  ValidatedCb _cb);
    
    void validate();

  private:
    void path_found_cb(boost::shared_ptr<WvX509Path> &path, WvError err);
    typedef std::map< std::string, boost::shared_ptr<PathFinder> > PathFinderMap;
    typedef std::pair< std::string, boost::shared_ptr<PathFinder> > PathFinderPair;
    PathFinderMap pathfinder_map;

    boost::shared_ptr<WvX509> cert_to_be_validated;
    WvStringList initial_policy_set;
    uint32_t validation_flags;

    boost::shared_ptr<WvX509Store> trusted_store;
    boost::shared_ptr<WvX509Store> intermediate_store;

    UniConf cfg;
    ValidatedCb validated_cb;

    WvLog log;
};

#endif // __PATHVALIDATOR_H
