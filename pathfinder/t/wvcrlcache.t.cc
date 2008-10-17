#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <wvfileutils.h>
#include <wvtest.h>
#include "wvcrlcache.h"
#include "wvstrutils.h"
#include "testmethods.t.h"

using namespace boost;


WVTEST_MAIN("crlcache basic")
{
    WvString dirname("/tmp/pathfinder-crlcache-%s", getpid());
    WvString crlloc = WvString("%s/%s", dirname, 
                               url_encode("http://foohost/Trust.crl"));
    mkdirp(dirname);
    fcopy(CRLS_PATH "TrustAnchorRootCRL.crl", crlloc);

    WvCRLCache store(dirname);

    WVPASS(store.get_url("http://foohost/Trust.crl"));
    WVFAIL(store.get_url("http://foohost/Trust2.crl"));
    WVPASS(store.get_file(crlloc));
    WVFAIL(store.get_file(WvString("/%s/my-imaginary-non-existent-file", 
                                   dirname)));

    WVPASSEQ(store.get_url("http://foohost/Trust.crl")->get_aki(),
             "FB:6C:D4:2D:81:9E:CA:27:7A:9E:0D:B0:3C:EA:9A:BC:87:FF:49:EA");

    // replace the crl with something completely different
    fcopy(CRLS_PATH "GoodCACRL.crl", crlloc);

    time_t real_new_file_time = time(NULL) + 5000;
    utimbuf buf;
    buf.actime = real_new_file_time;
    buf.modtime = real_new_file_time;
    utime(crlloc, &buf);

    WVPASSEQ(store.get_url("http://foohost/Trust.crl")->get_aki(),
             "B7:2E:A6:82:CB:C2:C8:BC:A8:7B:27:44:D7:35:33:DF:9A:15:94:C7");
    WVPASSEQ(store.get_file(crlloc)->get_aki(),
             "B7:2E:A6:82:CB:C2:C8:BC:A8:7B:27:44:D7:35:33:DF:9A:15:94:C7");

    // set the crl back to what it was, but make sure the modtime is the same:
    // wvcrlcache should use the previous version
    fcopy(CRLS_PATH "TrustAnchorRootCRL.crl", crlloc);
    utime(crlloc, &buf);
    WVPASSEQ(store.get_url("http://foohost/Trust.crl")->get_aki(),
             "B7:2E:A6:82:CB:C2:C8:BC:A8:7B:27:44:D7:35:33:DF:9A:15:94:C7");
    WVPASSEQ(store.get_file(crlloc)->get_aki(),
             "B7:2E:A6:82:CB:C2:C8:BC:A8:7B:27:44:D7:35:33:DF:9A:15:94:C7");

    rm_rf(dirname);
}

