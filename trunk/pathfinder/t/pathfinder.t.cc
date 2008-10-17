#include <uniconfroot.h>
#include <wvtest.h>

#define private public
#include "pathfinder.h"
#undef private
#include "testmethods.t.h"

using namespace boost;
using namespace std;

// currently disabled because carillon's ocsp server is still in testing
#if 0
static void path_found_cb_ocsp(shared_ptr<WvX509Path> &path, WvError err,
                               shared_ptr<WvX509> &cert, int &found_count)
{
    found_count++;
    WVFAIL(err.geterr());
    if (err.geterr())
    {
        wvcon->print("ERROR: %s\n", err.errstr());       
        return;
    }

    pair<WvX509Path::OCSPRespMap::iterator, WvX509Path::OCSPRespMap::iterator> iterpair = 
    path->ocsp_map.equal_range(cert->get_ski().cstr());

    
    WVFAIL(iterpair.first == iterpair.second); // WVFAILEQ doesn't work here

    if (iterpair.first != iterpair.second)
    {
        shared_ptr<WvOCSPResp> resp = (*iterpair.first).second;
        WVPASS(resp->isok());
    }
}


WVTEST_MAIN("ocsp checking")
{
    WvHttpStream::global_enable_pipelining = false;

    UniConfRoot cfg("temp:");
    shared_ptr<WvX509Store> trusted_store(new WvX509Store);
    shared_ptr<WvX509Store> intermediate_store(new WvX509Store);
    shared_ptr<WvCRLCache> crlcache(new WvCRLCache("/tmp/does-not-exist-no"));

    shared_ptr<WvX509> cert(new WvX509);
    cert->decode(WvX509::CertFilePEM, WvString("%s%s", CERTS_PATH, 
                                               "carillon-invalid-ocsp.pem"));
    shared_ptr<WvX509> cacert(new WvX509);
    cacert->decode(WvX509::CertFilePEM, WvString("%s%s", CERTS_PATH, 
                                               "carillon-root-ca.pem"));
    trusted_store->add_cert(cacert);

    int found_count = 0;
    PathFinder p(cert, trusted_store, 
                 intermediate_store, crlcache, 0, cfg, 
                 wv::bind(&path_found_cb_ocsp, _1, _2,
                          wv::ref(cert),
                          wv::ref(found_count)));
    p.find();

    while (!found_count)
        WvIStreamList::globallist.runonce();

    WVPASSEQ(found_count, 1);
}
#endif
