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
#include "wvdbusconn.h"

#include "pathvalidator.h"
#include "version.h"
#include "wvx509store.h"

using namespace boost;
using namespace std;

#define DEFAULT_CONFIG_MONIKER "ini:/etc/pathfinderd.conf"
#define DEFAULT_DBUS_MONIKER "dbus:system"


class PathFinderDaemon : public WvStreamsDaemon
{
public:
    PathFinderDaemon() :
        WvStreamsDaemon("pathfinderd", PATHFINDER_VERSION, 
                        wv::bind(&PathFinderDaemon::cb, this)),
        dbusconn(NULL),
        cfgmoniker(DEFAULT_CONFIG_MONIKER),
        dbusmoniker(DEFAULT_DBUS_MONIKER)
    {
        trusted_store = shared_ptr<WvX509Store>(new WvX509Store);
        intermediate_store = shared_ptr<WvX509Store>(new WvX509Store);

        args.add_option('c', "config", WvString("Config moniker (default: %s)",
                                                DEFAULT_CONFIG_MONIKER),
                        "ini:filename.ini", cfgmoniker);
        args.add_option('m', "moniker", 
                        WvString("Specify the D-Bus moniker to use (default: "
                                 "%s)", DEFAULT_DBUS_MONIKER), 
                        "MONIKER", dbusmoniker);
    }
   
    virtual ~PathFinderDaemon()
    {
        dbusconn->del_callback(this);
        WVRELEASE(dbusconn);
    }

    void cb()
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
        dbusconn = new WvDBusConn(dbusmoniker);
        dbusconn->request_name("ca.carillon.pathfinder");
        // FIXME: need to check for success of name request

        dbusconn->add_callback(WvDBusConn::PriNormal, 
                               wv::bind(&PathFinderDaemon::incoming, this, 
                                        _1), this);
        add_die_stream(dbusconn, true, "wvdbus conn");
    }                          

    bool incoming(WvDBusMsg &msg)        
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
        
        fprintf(stderr, "\n * %s\n\n", ((WvString)msg).cstr());

        WvDBusMsg::Iter args(msg);
	WvString certhex = args.getnext();
        WvString initial_policy_set_tcl = args.getnext();
        bool inital_explicit_policy = args.getnext();
        bool initial_policy_mapping_inhibit = args.getnext();

        shared_ptr<WvX509> cert(new WvX509());
        cert->decode(WvX509::CertHex, certhex);
        if (!cert->isok())
        {
            log(WvLog::Warning, "Received a request to validate an invalid "
                "certificate. Aborting.\n");
            dbusconn->send(msg.reply().append(false));
            return true;
        }

        log("Received a request to validate certificate with subject %s.\n", 
            cert->get_subject());

        WvDBusMsg *reply = new WvDBusMsg(msg.reply());
            
        uint32_t flags = 0;
        if (cfg["verification options"].xgetint("skip crl check", 0))
        {
            log("Skipping CRL checking as specified in configuration.\n");
            flags |= WVX509_SKIP_CRL_CHECK;
        }
        if (inital_explicit_policy)
            flags |= WVX509_INITIAL_EXPLICIT_POLICY;
        if (initial_policy_mapping_inhibit)
            flags |= WVX509_INITIAL_POLICY_MAPPING_INHIBIT;

        PathValidator::ValidatedCb cb = wv::bind(
            &PathFinderDaemon::path_validated_cb, this, _1, _2, _3, _4);
        PathValidator *pv = new PathValidator(cert, initial_policy_set_tcl, 
                                              flags, trusted_store, 
                                              intermediate_store, cfg, 
                                              cb, reply);
        shared_ptr<PathValidator> validator(pv);
        validatormap.insert(
            pair< WvDBusMsg *, shared_ptr<PathValidator> >(reply, validator));
        validator->validate();

        return true;
    }


    void path_validated_cb(boost::shared_ptr<WvX509> &cert, bool valid, 
                           WvError err, void *userdata)
    {
        WvDBusMsg *reply = static_cast<WvDBusMsg *>(userdata);

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

    
    WvDBusConn *dbusconn;
    shared_ptr<WvX509Store> trusted_store;
    shared_ptr<WvX509Store> intermediate_store;
    typedef std::map<WvDBusMsg *, boost::shared_ptr<PathValidator> > ValidatorMap;
    ValidatorMap validatormap;
    WvString cfgmoniker;
    WvString dbusmoniker;
    UniConfRoot cfg;
};


int main(int argc, char *argv[])
{
    return PathFinderDaemon().run(argc, argv);
}

