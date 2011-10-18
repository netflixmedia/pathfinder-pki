/*
 * pathvalidator.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include "pathvalidator.h"
#include "wvx509policytree.h"

using namespace boost;
using namespace std;


PathValidator::PathValidator(shared_ptr<WvX509> &_cert,
                             WvStringParm _initial_policy_set_tcl, 
                             uint32_t _validation_flags,
                             shared_ptr<WvX509Store> &_trusted_store,
                             shared_ptr<WvX509Store> &_intermediate_store,
                             shared_ptr<WvX509Store> &_fetched_store,
                             shared_ptr<WvCRLCache> &_crlcache,
                             UniConf &_cfg, 
                             ValidatedCb _cb) :
    cert_to_be_validated(_cert),
    validation_flags(_validation_flags),
    trusted_store(_trusted_store),
    intermediate_store(_intermediate_store),
    fetched_store(_fetched_store),
    crlcache(_crlcache),
    cfg(_cfg),
    validated_cb(_cb),
    log(WvString("Path validator for certificate %s", _cert->get_subject()))
{
    wvtcl_decode(initial_policy_set, _initial_policy_set_tcl);
    certs_to_be_validated.push_back(_cert);
}


void PathValidator::validate(bool check_ocsp)
{
    shared_ptr<WvX509> cert(certs_to_be_validated.front());
    certs_to_be_validated.pop_front();
    
    PathFoundCb cb = wv::bind(&PathValidator::path_found_cb, this, _1, _2, 
                              cert);
    shared_ptr<PathFinder> pathfinder(new PathFinder(cert,
                                                     trusted_store,
                                                     intermediate_store,
                                                     fetched_store,
                                                     crlcache,
                                                     validation_flags,
                                                     check_ocsp,
                                                     cfg, cb));
    pathfinder_list.push_front(pathfinder); // just to keep a reference to it

    pathfinder->find();
}


void PathValidator::path_found_cb(shared_ptr<WvX509Path> &path, WvError err, 
                                  shared_ptr<WvX509> &cert)
{
    if (!err.isok())
    {
        log("Encountered error (%s) during path discovery. Aborting.\n", 
            err.errstr());
        // FIXME: abort all pathfinding activities.
        validated_cb(cert_to_be_validated, false, err);
        return;
    }

    WvX509List extra_certs;
    bool valid = path->validate(trusted_store, intermediate_store, 
                                fetched_store, initial_policy_set,
                                validation_flags, extra_certs, err);
    log("Path validated for certificate %s, certificate is %svalid.\n", 
        cert->get_subject(), valid ? "" : "NOT ");
   
    if (!extra_certs.empty())
    {
        log("Additional certificates must be validated before the path can "
            "be said to be valid.\n");
        while (!extra_certs.empty())
        {
            certs_to_be_validated.push_back(extra_certs.front());
            extra_certs.pop_front();
        }
        validate(false); // not checking OCSP, as that can get circular
        return;
    }

    validated_cb(cert_to_be_validated, valid, err);
}


