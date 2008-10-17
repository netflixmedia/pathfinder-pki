/*
 * pathfinderd.cc
 *
 * Copyright (C) 2007-2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <boost/shared_ptr.hpp>
#include <uniconfroot.h>
#include <wvargs.h>
#include <wvdbusconn.h>
#include <wvstreamsdaemon.h>

#include "pathserver.h"
#include "version.h"
#include "wvx509path.h"
#include "wvcrlcache.h"

using namespace boost;

#define DEFAULT_CONFIG_MONIKER "ini:/etc/pathfinderd.conf"
#define DEFAULT_DBUS_MONIKER "dbus:system"
#define DEFAULT_CRLSTORE_LOCATION "/var/cache/pathfinder/crls/"


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
   
    void cb()
    {
        WvHttpStream::global_enable_pipelining = false;
    
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
        
        crlstore = shared_ptr<WvCRLCache>(
            new WvCRLCache(cfg["general"].xget("crl cache location", 
                                               DEFAULT_CRLSTORE_LOCATION)));

	
        // Initialize D-Bus
        dbusconn = new WvDBusConn(dbusmoniker);
        dbusconn->request_name("ca.carillon.pathfinder");
        // FIXME: need to check for success of name request
        add_die_stream(dbusconn, true, "wvdbus conn");
        
        // Initialize pathfinder "server" object
        pathserver = new PathServer(trusted_store, intermediate_store,
                                    crlstore, cfg);
        dbusconn->add_callback(WvDBusConn::PriNormal, 
                               wv::bind(&PathServer::incoming, pathserver, 
                                        dbusconn, _1), this);
    }
    
    shared_ptr<WvX509Store> trusted_store;
    shared_ptr<WvX509Store> intermediate_store;
    shared_ptr<WvCRLCache> crlstore;
    WvDBusConn *dbusconn;
    PathServer *pathserver;
    WvString cfgmoniker;
    WvString dbusmoniker;

    UniConfRoot cfg;
};


int main(int argc, char *argv[])
{
    return PathFinderDaemon().run(argc, argv);
}

