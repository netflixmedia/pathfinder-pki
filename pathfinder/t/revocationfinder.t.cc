#include <uniconfroot.h>
#include <wvfile.h>
#include <wvfileutils.h>
#include <wvstrutils.h>
#include <wvtcplistener.h>
#include <wvtest.h>
#include <wvx509mgr.h>

#include "testdefuns.t.h"
#include "util.h"
#define private public
#include "revocationfinder.h" 
#undef private
using namespace boost;


static void accept_callback_crl(IWvStream *_conn, WvBuf &stuff)
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
    UniConfRoot cfg("temp:");

    WvString crlcache_dir("/tmp/pathfinder-crlcache-%s", getpid());
    rm_rf(crlcache_dir);
    shared_ptr<WvCRLCache> crlcache(new WvCRLCache(crlcache_dir));

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
    sock.onaccept(wv::bind(accept_callback_crl, _1, wv::ref(buf)));
    WvIStreamList::globallist.append(&sock, false, "http listener");
        
    wvcon->print("Listening for requests on port %s\n", *sock.src());

    shared_ptr<WvX509Path> path(new WvX509Path);
    int found_info_cb_count = 0;
    shared_ptr<WvX509> cacert(new WvX509(ca));
    RevocationFinder finder(cert, cacert, path, crlcache, false, cfg, 
                            wv::bind(&found_revocation_info, _1, 
                                     wv::ref(found_info_cb_count)));

    while (!found_info_cb_count)
        WvIStreamList::globallist.runonce();
        
    WVPASSEQ(path->crl_map.count(cert->get_subject().cstr()), 1);   
    WvIStreamList::globallist.zap();
}


WVTEST_MAIN("explicit crls")
{
    WvString crlcache_dir("/tmp/pathfinder-crlcache-%s", getpid());
    rm_rf(crlcache_dir);
    shared_ptr<WvCRLCache> crlcache(new WvCRLCache(crlcache_dir));
    UniConfRoot cfg("temp:");

    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    WvCRL crl(ca);
    WvString crl_filename = wvtmpfilename("crltest");
    {
        WvDynBuf buf;
        crl.encode(WvCRL::CRLPEM, buf);
        WvFile f(crl_filename, O_CREAT|O_WRONLY);
        f.write(buf);
    }

    WvRSAKey rsakey(DEFAULT_KEYLEN);
    WvString certreq 
	= WvX509Mgr::certreq("cn=test.signed.com,dc=signed,dc=com", rsakey);
    shared_ptr<WvX509> cert(new WvX509);
    WvString certpem = ca.signreq(certreq);
    cert->decode(WvX509Mgr::CertPEM, certpem);
    cfg["CRL Location"].xset(url_encode(cert->get_issuer(), "/"), 
                             crl_filename);

    shared_ptr<WvX509Path> path(new WvX509Path);
    int found_info_cb_count = 0;
    shared_ptr<WvX509> cacert(new WvX509(ca));

    RevocationFinder finder(cert, cacert, path, crlcache, false, cfg,
                            wv::bind(&found_revocation_info, _1, 
                                     wv::ref(found_info_cb_count)));
    WVPASSEQ(path->crl_map.count(cert->get_subject().cstr()), 1);   

    ::unlink(crl_filename);
}


// FIXME: would be nice to have some OCSP tests, but setting up a working
// responder locally is a pain...
