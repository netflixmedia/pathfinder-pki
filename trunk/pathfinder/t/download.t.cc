#include <wvtest.h>
#include <wvlogrcv.h>
#include "downloader.h"

WVTEST_MAIN("HTTP Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");
    Downloader d("http://www.carillon.ca/caops", p, NULL);
    while (!d.is_done())
        WvIStreamList::globallist.runonce();
    
}

WVTEST_MAIN("LDAP Download")
{
    WvHttpPool *p = new WvHttpPool();
    
    WvIStreamList::globallist.append(p, false, "WvHttpPool");
    Downloader d("ldap://dir.carillon.ca/", p, NULL);
    while (!d.is_done())
        WvIStreamList::globallist.runonce();
}
