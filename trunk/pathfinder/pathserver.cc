/*
 * pathserver.cc
 *
 * Copyright (C) 2007-2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include "pathserver.h"
#include "wvx509policytree.h"

using namespace boost;
using namespace std;


PathServer::PathServer(shared_ptr<WvX509Store> _trusted_store,
                       shared_ptr<WvX509Store> _intermediate_store,
                       shared_ptr<WvCRLCache> _crlcache,
                       UniConf &_cfg) :
    log("PathFinder"),
    cfg(_cfg)
{
    trusted_store = _trusted_store;
    intermediate_store = _intermediate_store;
    crlcache = _crlcache;
}


bool PathServer::incoming(WvDBusConn *conn, WvDBusMsg &msg)        
{
    if (msg.get_dest() != "ca.carillon.pathfinder" || 
        msg.get_path() != "/ca/carillon/pathfinder") 
        return false;
    
    // I guess it's for us!
    WvString method(msg.get_member());
    
    if (method != "validate") 
    {
        log(WvLog::Warning, "Got a message asking for unknown method "
            "'%s'.\n", method);
        return true;
    }

    WvDBusMsg::Iter args(msg);
    WvString certhex = args.getnext();
    WvString initial_policy_set_tcl = args.getnext();
    bool initial_explicit_policy = args.getnext();
    bool initial_policy_mapping_inhibit = args.getnext();
    // appname is strictly optional, as pathfinder did not always support
    // the option
    WvString appname = args.getnext();
    
    shared_ptr<WvX509> cert(new WvX509());
    cert->decode(WvX509::CertHex, certhex);
    if (!cert->isok())
    {
        log(WvLog::Warning, "Received a request to validate an invalid "
            "certificate. Aborting.\n");
        conn->send(msg.reply().append(false));
        return true;
    }

    log("Received a request to validate certificate with subject %s.\n", 
        cert->get_subject());
    
    WvDBusMsg *reply = new WvDBusMsg(msg.reply());
    
    uint32_t flags = 0;
    if (cfg["verification options"].xgetint("skip revocation check", 0))
    {
        log("Skipping revocation checking as specified in configuration.\n");
        flags |= WVX509_SKIP_REVOCATION_CHECK;
    }
    if (initial_explicit_policy)
        flags |= WVX509_INITIAL_EXPLICIT_POLICY;
    if (initial_policy_mapping_inhibit)
        flags |= WVX509_INITIAL_POLICY_MAPPING_INHIBIT;

    // check policy input: if it's anyPolicy, we want to use the default
    // policy for the "app" (falling back again to ANY_POLICY if there
    // is nothing specified)
    WvStringList initial_policy_set;
    wvtcl_decode(initial_policy_set, initial_policy_set_tcl);
    if (initial_policy_set.count() == 1 && 
        initial_policy_set.popstr() == ANY_POLICY_OID &&
        !!appname)
    {
        initial_policy_set_tcl = cfg["policy"].xget(appname, ANY_POLICY_OID);
        log("Using special policy %s for appname %s.\n", 
            initial_policy_set_tcl, appname);
        if (!initial_explicit_policy)
        {
            WvStringList new_initial_policy_set;
            wvtcl_decode(new_initial_policy_set, initial_policy_set_tcl);
            if (new_initial_policy_set.count() != 1 ||
                new_initial_policy_set.popstr() != ANY_POLICY_OID)
            {
                log("Setting initial_explicit_policy, even though it was "
                    "previously unset, to force that specify policy to "
                    "match.");
                initial_explicit_policy = true;
                flags |= WVX509_INITIAL_EXPLICIT_POLICY;
            }
        }
    }
    
    PathValidator::ValidatedCb cb = wv::bind(
        &PathServer::path_validated_cb, this, _1, _2, _3, conn, reply);
    PathValidator *pv = new PathValidator(cert, initial_policy_set_tcl, 
                                          flags, trusted_store, 
                                          intermediate_store, crlcache, cfg, 
                                          cb);
    shared_ptr<PathValidator> validator(pv);
    validatormap.insert(
        pair< WvDBusMsg *, shared_ptr<PathValidator> >(reply, validator));

    switch(cfg["Verification Options"].xgetint("Use OCSP", 1))
    {
         case 0:
               validator->validate(false);
               break;            
         case 1:
         case 2:
               validator->validate(true);
               break;           
         default:
               log(WvLog::Warning, "Unrecognised value for 'Use OCSP' found.\n"
                                   "Treating as default of '1'!\n");           
               validator->validate(true);                                             
    }
        
    return true;
}


void PathServer::path_validated_cb(shared_ptr<WvX509> &cert, bool valid, 
                                   WvError err, WvDBusConn *conn, 
                                   WvDBusMsg *reply)
{
    uint32_t flags = 0;
    log("Path validated for certificate %s. Result: %svalid\n", 
        cert->get_subject(), valid ? "" : "NOT ");
    validatormap.erase(reply);
    
    // send reply
    reply->append(valid);
    reply->append(err.errstr());
    conn->send(*reply);
    WVDELETE(reply);
}
