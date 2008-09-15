#include <uniconfroot.h>
#include <wvdbusconn.h>
#include <wvdbusserver.h>

#include "testmethods.t.h"
#include "pathserver.h"

using namespace boost;


// shamelessly copied from wvdbusserver.t.cc in wvstreams
class TestDBusServer
{
public:
    WvString moniker;
    WvDBusServer *s;
    
    TestDBusServer()
    {
	fprintf(stderr, "Creating a test DBus server.\n");
	// We might prefer to use a unix: moniker, but get_addr() only
	// supports tcp: monikers just now.
	WvString smoniker("tcp:0.0.0.0");
	s = new WvDBusServer();
	s->listen(smoniker);
	moniker = s->get_addr();
	fprintf(stderr, "Server address is '%s'\n", moniker.cstr());
	WvIStreamList::globallist.append(s, false, "dbus server");
    }
    
    ~TestDBusServer()
    {
	WVRELEASE(s);
        /* Flush connections out of the globallist, necessary to trigger
         * the actual killing of the WvDBusServer object (it's ref-
         * counted based on #connections).  No self-respecting program would
         * need to do this, but we don't want Valgrind thinking we're leaking
         * memory, or the open file descriptor checker freaking out.
         */
        for (int i = 0; i < 1; ++i)
            WvIStreamList::globallist.runonce();
        WVPASS(WvIStreamList::globallist.isempty());
    }
};


static int myreply_count = 0;
static bool myreply_ok = false;

static bool myreply(WvDBusMsg &msg)
{
    myreply_count++;

    WvDBusMsg::Iter args(msg);
    myreply_ok = args.getnext();

    wvcon->print("got reply: ok %s count %s\n", myreply_ok, myreply_count);

    return true; 
}


WVTEST_MAIN("pathserver basic")
{
    TestDBusServer serv;
    WvDBusConn conn1(serv.moniker);
    WvIStreamList::globallist.append(&conn1, false, "dbus connection");
    
    conn1.request_name("ca.carillon.pathfinder");

    UniConfRoot cfg("temp:");
    shared_ptr<WvX509Store> trusted_store(new WvX509Store);
    shared_ptr<WvX509Store> intermediate_store(new WvX509Store);

    PathServer pathserver(trusted_store, intermediate_store,
                          cfg);
    conn1.add_callback(WvDBusConn::PriNormal, 
                       wv::bind(&PathServer::incoming, pathserver, 
                                &conn1, _1), &pathserver);

    WvX509 x509;
    x509.decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, 
                                           "GoodCACert.crt"));

    WvDBusMsg msg("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                  "ca.carillon.pathfinder", "validate");
    msg.append(x509.encode(WvX509::CertHex));
    msg.append(WvString(ANY_POLICY_OID));
    msg.append(false);
    msg.append(false);

    conn1.send(msg, myreply);

    while (myreply_count < 1)
        WvIStreamList::globallist.runonce();

    WVPASSEQ(myreply_count, 1);
    WVFAILEQ(myreply_ok, 1);
}
