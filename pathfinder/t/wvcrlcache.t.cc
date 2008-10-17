#include <sys/types.h>
#include <unistd.h>
#include <wvfileutils.h>
#include <wvtest.h>
#include "wvcrlcache.h"
#include "wvstrutils.h"
#include "testmethods.t.h"

using namespace boost;


WVTEST_MAIN("crlstore basic")
{
    WvString dirname("/tmp/pathfinder-crlstore-%s", getpid());
    mkdirp(dirname);
    fcopy(CRLS_PATH "TrustAnchorRootCRL.crl", 
          WvString("%s/%s", dirname,
                   url_encode("http://foohost/TrustAnchorRootCRL.crl")));

    WvCRLCache store(dirname);

    WVPASS(store.exists("http://foohost/TrustAnchorRootCRL.crl"));
    WVFAIL(store.exists("http://foohost/TrustAnchorRootCRL2.crl"));
    
    shared_ptr<WvCRL> crl = store.get(
        "http://foohost/TrustAnchorRootCRL.crl");

    WVPASSEQ(crl->get_aki(), 
             "FB:6C:D4:2D:81:9E:CA:27:7A:9E:0D:B0:3C:EA:9A:BC:87:FF:49:EA");

    rm_rf(dirname);
}

