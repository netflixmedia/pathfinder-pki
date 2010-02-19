#include <wvtest.h>
#include <wvlogrcv.h>
#include "downloader.h"

WVTEST_MAIN("HTTP Download")
{
    WvHTTPPool *p = new WvHTTPPool();
    WvIStreamList l;
    l.append(p, false, "WvHttpPool");
    Downloader d("http://www.carillon.ca/caops", p, null);
    while (!d->is_done())
        l.runonce();
    
}

WVTEST_MAIN("LDAP Download")
{
    WvHTTPPool *p = new WvHTTPPool();
    WvIStreamList l;
    l.append(p, false, "WvHttpPool");
    Downloader d("ldap://dir.carillon.ca/", p, null);
    while (!d->is_done())
        l.runonce();
}