/*
 * pathvalidator.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include "pathvalidator.h"

using namespace boost;
using namespace std;


PathValidator::PathValidator(shared_ptr<WvX509> &_cert,
                             WvStringParm _initial_policy_set_tcl, 
                             uint32_t _validation_flags,
                             shared_ptr<WvX509Store> &_trusted_store,
                             shared_ptr<WvX509Store> &_intermediate_store,
                             UniConf &_cfg, 
                             ValidatedCb _cb, void *_userdata) :
    cert_to_be_validated(_cert),
    validation_flags(_validation_flags),
    trusted_store(_trusted_store),
    intermediate_store(_intermediate_store),
    userdata(_userdata),
    cfg(_cfg),
    validated_cb(_cb),
    log("Path Validator")
{
    wvtcl_decode(initial_policy_set, _initial_policy_set_tcl);
}


void PathValidator::validate()
{
    PathFoundCb cb(this, &PathValidator::path_found_cb);
    boost::shared_ptr<PathFinder> pathfinder(new PathFinder(cert_to_be_validated,
                                                            trusted_store,
                                                            intermediate_store,
                                                            validation_flags,
                                                            cfg, cb, NULL));

    pathfinder_map.insert(PathFinderPair(cert_to_be_validated->get_ski().cstr(),
                                         pathfinder));                                                            

    pathfinder->find();
}


void PathValidator::path_found_cb(shared_ptr<WvX509Path> &path, WvError err, void *)
{
    if (!err.isok())
    {
        log("Encountered error (%s) during path discovery. Aborting.\n", err.errstr());
        // FIXME: abort all pathfinding activities.
        validated_cb(cert_to_be_validated, false, err, userdata);
        return;
    }

    WvX509Path::WvX509List extra_certs;
    bool valid = path->validate(trusted_store, intermediate_store, 
                                initial_policy_set, validation_flags, 
                                extra_certs, err);
    log("Initial path validated, certificate is %svalid.\n", valid ? "" : "NOT ");
   
    if (!extra_certs.empty())
    {
        log("There are %s extra certificates to be processed before the path can "
            "be said to be valid. This is not yet supported.\n", extra_certs.size());
        valid = false;
    }

    validated_cb(cert_to_be_validated, valid, err, userdata);
}


