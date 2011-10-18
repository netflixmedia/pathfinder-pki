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
#define DEFAULT_FETCHEDSTORE_LOCATION "/var/cache/pathfinder/fetched/"


class PathFinderDaemon : public WvStreamsDaemon
{
public:
    PathFinderDaemon() :
        WvStreamsDaemon("pathfinderd", PATHFINDER_VERSION, 
                        wv::bind(&PathFinderDaemon::cb, this)),
        dbusconn(NULL),
        cfgmoniker(DEFAULT_CONFIG_MONIKER),
        dbusmoniker(DEFAULT_DBUS_MONIKER),
        fips_mode(false)
    {
        trusted_store = shared_ptr<WvX509Store>(new WvX509Store);
        intermediate_store = shared_ptr<WvX509Store>(new WvX509Store);
        fetched_store = shared_ptr<WvX509Store>(new WvX509Store);
        args.add_option(0, "pid-file",
                        "Specify the .pid file to use (only applies with --daemonize)", "filename",
                        pid_file);

        args.add_option('c', "config", WvString("Config moniker (default: %s)",
                                                DEFAULT_CONFIG_MONIKER),
                        "ini:filename.ini", cfgmoniker);
        args.add_option('m', "moniker", 
                        WvString("Specify the D-Bus moniker to use (default: "
                                 "%s)", DEFAULT_DBUS_MONIKER), 
                        "MONIKER", dbusmoniker);
#ifdef OPENSSL_FIPS
        args.add_set_bool_option('f', "fips", WvString("Enable FIPS mode crypto "
                                              "(default: OFF)"), fips_mode);
#endif
    }
   
    void cb()
    {
        WvHttpStream::global_enable_pipelining = false;
    
#ifdef OPENSSL_FIPS        
        if (fips_mode)
        {
          // do something here that enables fips.
          if (!FIPS_mode_set(1))
          {
            log(WvLog::Error, "FIPS mode requested, but not enabled!\n");
          }
          else
          {
            log(WvLog::Info, "FIPS mode is enabled.\n");
          }
        }
#endif
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

        {
            WvString loc(cfg["general"].xget("fetched store location",
                                             DEFAULT_FETCHEDSTORE_LOCATION));
            fetched_store->set_storedir(loc);
        }
        
        crlcache = shared_ptr<WvCRLCache>(
            new WvCRLCache(cfg["general"].xget("crl cache location", 
                                               DEFAULT_CRLSTORE_LOCATION)));

	
        // Initialize D-Bus
        // HACK: dbus:system doesn't correspond to anything useful most of the
        // time, use a hardcoded value instead
        if (dbusmoniker == "dbus:system")
            dbusmoniker = "unix:/var/run/dbus/system_bus_socket";
        dbusconn = new WvDBusConn(dbusmoniker);
        dbusconn->request_name("ca.carillon.pathfinder");
        // FIXME: need to check for success of name request
        add_die_stream(dbusconn, true, "wvdbus conn");
        
        // Initialize pathfinder "server" object
        pathserver = new PathServer(trusted_store, intermediate_store,
                                    fetched_store, crlcache, cfg);
        dbusconn->add_callback(WvDBusConn::PriNormal, 
                               wv::bind(&PathServer::incoming, pathserver, 
                                        dbusconn, _1), this);
    }
    
    shared_ptr<WvX509Store> trusted_store;
    shared_ptr<WvX509Store> intermediate_store;
    shared_ptr<WvX509Store> fetched_store;
    shared_ptr<WvCRLCache> crlcache;
    WvDBusConn *dbusconn;
    PathServer *pathserver;
    WvString cfgmoniker;
    WvString dbusmoniker;
    bool fips_mode;

    UniConfRoot cfg;
};


int main(int argc, char *argv[])
{
    return PathFinderDaemon().run(argc, argv);
}

