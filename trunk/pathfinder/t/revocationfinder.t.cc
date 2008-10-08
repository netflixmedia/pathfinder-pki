#include <wvfile.h>
#include <wvfileutils.h>
#include <wvtcplistener.h>
#include <wvtest.h>
#include <wvx509mgr.h>

#include "testdefuns.t.h"
#define private public
#include "revocationfinder.h" 
#undef private
using namespace boost;


static void accept_callback(IWvStream *_conn, WvBuf &stuff)
{
    WvDynBuf header;
    header.putstr(WvString("HTTP/1.1 200 OK\n"
                          "Content-Length: %s\n"
                          "Content-Type: text/html\n\n",
                           stuff.used()));

    _conn->write(header);
    _conn->write(stuff);
    _conn->close();
    WvIStreamList::globallist.append(_conn, true, "http server conn");
}


static void found_revocation_info(WvError &err, int &found_info_cb_count)
{
    found_info_cb_count++;
}


WVTEST_MAIN("multiple lookups required")
{
    srandom(time(NULL));
    WvHttpStream::global_enable_pipelining = false;

    // FIXME: dumb assumption that these ports will be free...
    const int portstart = 8000;

    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    WvCRL crl(ca);
    WvDynBuf buf;
    crl.encode(WvCRL::CRLPEM, buf);

    WvRSAKey rsakey(DEFAULT_KEYLEN);
    WvString certreq 
	= WvX509Mgr::certreq("cn=test.signed.com,dc=signed,dc=com", rsakey);
    shared_ptr<WvX509> cert(new WvX509);
    WvString certpem = ca.signreq(certreq);
    cert->decode(WvX509Mgr::CertPEM, certpem);
    WvStringList crl_urls;
    for (int port = portstart; port < portstart + 3; port++)
        crl_urls.append(WvString("http://localhost:%s/foo.crl", port));
    cert->set_crl_urls(crl_urls);
    ca.signcert(*cert);

    WvTCPListener sock(WvString("localhost:%s", portstart + 2));
    sock.onaccept(wv::bind(accept_callback, _1, wv::ref(buf)));
    WvIStreamList::globallist.append(&sock, false, "http listener");

    wvcon->print("Listening for crl requests on port %s\n", *sock.src());

    shared_ptr<WvX509Path> path(new WvX509Path);
    WvString crlstore_dir("/tmp/pathfinder-crlstore-%s", getpid());
    rm_rf(crlstore_dir);
    shared_ptr<WvCRLStore> crlstore(new WvCRLStore(crlstore_dir));
    int found_info_cb_count = 0;
    RevocationFinder finder(cert, path, crlstore, 
                            wv::bind(&found_revocation_info, _1, 
                                     wv::ref(found_info_cb_count)));
    finder.find();

    while (!found_info_cb_count)
        WvIStreamList::globallist.runonce();

    WVPASSEQ(path->crl_map.count(cert->get_ski().cstr()), 1);   

    WvIStreamList::globallist.zap();
}
