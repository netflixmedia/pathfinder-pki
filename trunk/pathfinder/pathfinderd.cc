/*
 * pathfinderd.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <map>
#include <uniconfroot.h>
#include <wvargs.h>
#include <wvcrash.h>
#include <wvistreamlist.h>
#include <wvstreamsdaemon.h>
#include <xplc/ptr.h>
#include "wvdbusconn.h"
#include "wvdbuslistener.h"

#include "pathvalidator.h"
#include "version.h"
#include "wvx509store.h"

using namespace boost;
using namespace std;

#define DEFAULT_CONFIG_MONIKER "ini:/etc/pathfinderd.ini"


class PathFinderDaemon : public WvStreamsDaemon
{
public:
    typedef WvCallback<void, WvDBusConn&, WvDBusReplyMsg&, WvString, WvString, bool, bool, WvError> ValidateReqCb;

    PathFinderDaemon() :
        WvStreamsDaemon("pathfinderd", PATHFINDER_VERSION, 
                        WvStreamsDaemonCallback(this, &PathFinderDaemon::cb)),
        cfgmoniker(DEFAULT_CONFIG_MONIKER),
        session_bus(false)
    {
        trusted_store = shared_ptr<WvX509Store>(new WvX509Store);
        intermediate_store = shared_ptr<WvX509Store>(new WvX509Store);

        args.add_option('c', "config", WvString("Config moniker (default: %s)",
                                                DEFAULT_CONFIG_MONIKER),
                        "ini:filename.ini", cfgmoniker);
        args.add_set_bool_option('\0', "session", "Listen on the session "
                                 "bus (instead of the system bus)", 
                                 session_bus);
    }
    virtual ~PathFinderDaemon()
    {
        dbusconn->del_method("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                             "validate");
    }

    void cb(WvStreamsDaemon &daemon, void *)
    {
        // Mount config moniker
	cfg.unmount(cfg.whichmount(), true); // just in case
	cfg.mount(cfgmoniker);
	if (!cfg.whichmount() || !cfg.whichmount()->isok())
	{
	    log(WvLog::Error,
		"Can't read configuration from '%s'! Aborting.\n",
		cfgmoniker);
	    return;
	}

        // Load stores
        {
            UniConf::Iter i(cfg["trusted directories"]);
            for (i.rewind(); i.next();)
                trusted_store->load(i->getme());
        }
        {
            UniConf::Iter i(cfg["bridges"]);
            for (i.rewind(); i.next();)
                intermediate_store->add_pkcs7(i->getme());
        }
        // Initialize D-Bus
        WvDBusConn *conn = NULL;
        if (session_bus)
            conn = new WvDBusConn("ca.carillon.pathfinder", DBUS_BUS_SESSION);
        else
            conn = new WvDBusConn("ca.carillon.pathfinder", DBUS_BUS_SYSTEM);
        conn->addRef();
        WvIStreamList::globallist.append(conn, true, "wvdbus conn");
        dbusconn = conn;
        WvDBusMethodListener<WvString, WvString, bool, bool> *l = 
        new WvDBusMethodListener<WvString, WvString, bool, bool>(conn, "validate", 
                                              ValidateReqCb(this, &PathFinderDaemon::validate_req_cb));
        dbusconn->add_method("ca.carillon.pathfinder", "/ca/carillon/pathfinder", l);
        add_die_stream(conn, true, "wvdbus conn");
    }

    void validate_req_cb(WvDBusConn &conn, WvDBusReplyMsg &reply, WvString certpem, 
                         WvString initial_policy_set_tcl, bool inital_explicit_policy, 
                         bool initial_policy_mapping_inhibit, WvError err)
    {
        if (!err.isok())
        {
            log(WvLog::Warning, "Received a message, but there was an error (%s).\n",
                err.errstr().cstr());
            bool valid = false;
            reply.append(valid);
            dbusconn->send(reply);
            return;
        }

        shared_ptr<WvX509> cert(new WvX509());
        cert->decode(WvX509::CertHex, certpem);
        if (!cert->isok())
        {
            log(WvLog::Warning, "Received a request to validate an invalid "
                "certificate. Aborting.\n");
            bool valid = false;
            reply.append(valid);
            dbusconn->send(reply);
            return;
        }

        log("Received a request to validate certificate with subject %s.\n", cert->get_subject());
        PathValidator::ValidatedCb cb(this, &PathFinderDaemon::path_validated_cb);
        WvDBusReplyMsg *delayed_reply = new WvDBusReplyMsg(reply);

        uint32_t flags;
        if (cfg["verification options"].xgetint("skip crl check", 0))
        {
            log("Skipping CRL checking as specified in configuration.\n");
            flags |= WVX509_SKIP_CRL_CHECK;
        }
        if (inital_explicit_policy)
            flags |= WVX509_INITIAL_EXPLICIT_POLICY;
        if (initial_policy_mapping_inhibit)
            flags |= WVX509_INITIAL_POLICY_MAPPING_INHIBIT;

        shared_ptr<PathValidator> validator(new PathValidator(cert, initial_policy_set_tcl, flags, 
                                                              trusted_store, intermediate_store,
                                                              cfg, cb, delayed_reply));
        validatormap.insert(
            pair< WvDBusReplyMsg *, shared_ptr<PathValidator> >(delayed_reply, 
                                                                validator));
        validator->validate();
    }

    void path_validated_cb(boost::shared_ptr<WvX509> &cert, bool valid, WvError err,
                           void *userdata)
    {
        WvDBusReplyMsg *reply = static_cast<WvDBusReplyMsg *>(userdata);

        WvX509Path::WvX509List extra_certs;
        uint32_t flags = 0;
        log("Path validated for certificate %s. Result: %svalid\n", 
            cert->get_subject(), valid ? "" : "NOT ");
        validatormap.erase(reply);

        // send reply
        reply->append(valid);
        reply->append(err.errstr());
        dbusconn->send(*reply);
        WVDELETE(reply);
    }

    xplc_ptr<WvDBusConn> dbusconn;
    shared_ptr<WvX509Store> trusted_store;
    shared_ptr<WvX509Store> intermediate_store;
    typedef std::map<WvDBusReplyMsg *, boost::shared_ptr<PathValidator> > ValidatorMap;
    ValidatorMap validatormap;
    WvString cfgmoniker;
    UniConfRoot cfg;
    bool session_bus;
};


int main(int argc, char *argv[])
{
    return PathFinderDaemon().run(argc, argv);
}

