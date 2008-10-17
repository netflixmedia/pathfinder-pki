#include <uniconfroot.h>
#include <wvdbusconn.h>
#include <wvdbusserver.h>

#include "testmethods.t.h"
#include "pathserver.h"

using namespace boost;

// these tests are meant to test that the D-Bus interface to pathfinder
// are working as expected

// the following class is shamelessly copied from wvdbusserver.t.cc in 
// wvstreams
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


class PathServerTester
{
public:
    TestDBusServer serv;
    WvDBusConn *conn;
    UniConfRoot cfg;
    shared_ptr<WvX509Store> trusted_store;
    shared_ptr<WvX509Store> intermediate_store;
    shared_ptr<WvCRLCache> crlcache;
    PathServer pathserver;

    PathServerTester() : 
        cfg("temp:"),
        trusted_store(new WvX509Store),
        intermediate_store(new WvX509Store),
        crlcache(new WvCRLCache("/tmp/crlcache")),
        pathserver(trusted_store, intermediate_store, crlcache, cfg)
    {
    }

    ~PathServerTester() 
    {
        WVRELEASE(conn);
    }

    void init()
    {
        conn = new WvDBusConn(serv.moniker);
        WvIStreamList::globallist.append(conn, false, "dbus connection");
        conn->request_name("ca.carillon.pathfinder");
        
        conn->add_callback(WvDBusConn::PriNormal, 
                           wv::bind(&PathServer::incoming, pathserver, 
                                    conn, _1), &pathserver);
        
    }

    void add_trusted_cert(WvStringParm certname)
    {
        trusted_store->add_file(WvString("%s%s", CERTS_PATH, certname));
    }

    void add_untrusted_cert(WvStringParm certname)
    {
        intermediate_store->add_file(WvString("%s%s", CERTS_PATH, certname));
    }

    bool myreply(WvDBusMsg &msg, int &myreply_count, bool &myreply_ok)
    {
        myreply_count++;
        
        WvDBusMsg::Iter args(msg);
        myreply_ok = args.getnext();
        
        wvcon->print("got reply: ok %s count %s\n", myreply_ok, myreply_count);
        
        return true; 
    }

    bool test(WvStringParm certname, WvStringParm policy_set_tcl,
              bool initial_explicit_policy, 
              bool initial_policy_mapping_inhibit)
    {
        WvX509 x509;
        x509.decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, 
                                                  certname));

        WvDBusMsg msg("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                      "ca.carillon.pathfinder", "validate");
        msg.append(x509.encode(WvX509::CertHex));
        msg.append(policy_set_tcl);
        msg.append(initial_explicit_policy);
        msg.append(initial_policy_mapping_inhibit);
        msg.append("tester");

        int myreply_count = 0;
        bool myreply_ok = false;
        
        conn->send(msg, wv::bind(&PathServerTester::myreply, this,
                                        _1, wv::ref(myreply_count),
                                        wv::ref(myreply_ok)));
        while (myreply_count < 1)
            WvIStreamList::globallist.runonce();

        return myreply_ok;
    }
};


WVTEST_MAIN("pathserver basic")
{
    PathServerTester tester;
    tester.init();
    tester.cfg["verification options"].xsetint("skip revocation check", 1);

    // first test: don't have signing certificate in trusted store, should
    // fail
    WVFAIL(tester.test("GoodCACert.crt", ANY_POLICY_OID, false, false));

    // second test: DO have signing cert in trusted store, should pass
    // (note that we skip the CRL check in this test, otherwise it would
    // fail because no CRL dp is specified in the certificate)
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    WVPASS(tester.test("GoodCACert.crt", ANY_POLICY_OID, false, false));
}


WVTEST_MAIN("pathserver policies and appnames")
{
    // we re-use the suggested path from the path validation test 4.8.1
    // (certpolicies.t.cc) here

    PathServerTester tester;
    tester.init();
    tester.cfg["verification options"].xsetint("skip revocation check", 1);

    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");

    // first test: any policy oid, no override, no initial explicit policy,
    // should pass
    WVPASS(tester.test("ValidCertificatePathTest1EE.crt", ANY_POLICY_OID, 
                       false, false));
    // second test: nist tespolicy 1, should pass
    WVPASS(tester.test("ValidCertificatePathTest1EE.crt", NIST_TESTPOLICY_1, 
                           true, false));
    // third test: nist tespolicy 2, should fail
    WVFAIL(tester.test("ValidCertificatePathTest1EE.crt", NIST_TESTPOLICY_2, 
                       true, false));

    // test using NIST_TESTPOLICY_1 as an override and any policy oid, should 
    // pass
    tester.cfg["policy"].xset("tester", NIST_TESTPOLICY_1);
    WVPASS(tester.test("ValidCertificatePathTest1EE.crt", ANY_POLICY_OID, 
                       true, false));
    // test using NIST_TESTPOLICY_2 as an override and any policy oid, should 
    // fail
    tester.cfg["policy"].xset("tester", NIST_TESTPOLICY_2);
    WVFAIL(tester.test("ValidCertificatePathTest1EE.crt", ANY_POLICY_OID, 
                       true, false));
}
