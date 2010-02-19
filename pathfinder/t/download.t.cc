#include <wvtest.h>
#include <wvlogrcv.h>
#include "downloader.h"

static bool dl_pass = true;

void cb(WvStringParm s1, WvStringParm s2, WvBuf b, WvError err)
{
  if (err.geterr())
  {
      printf("Error was: %s\n", err.errstr().cstr());
      dl_pass = false;
      return;
  }
  else
  {
      dl_pass = true;
      return;
  }
}

WVTEST_MAIN("HTTP Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d("http://www.carillon.ca/caops/", p, cb);
    while (!d.is_done())
        WvIStreamList::globallist.runonce();
    WVPASS(dl_pass);
    delete p;
}

WVTEST_MAIN("LDAPS Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d1("ldaps://dir.carillon.ca/", p, cb);
    while (!d1.is_done())
        WvIStreamList::globallist.runonce();
    WVFAIL(dl_pass);
    delete p;
}

WVTEST_MAIN("Malformed LDAP URL Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d2("ldap://dir.carillon.ca/CN=TEST%20RSA%20Signing%20CA1"
                 ",OU=DEMO%20Certification%20Services,O=Carillon%20Information%20Security%20Inc.,C=CA?cACertificate;binary?base?objectclass=pkiCA", p, cb);
    while (!d2.is_done())
        WvIStreamList::globallist.runonce();
    WVFAIL(dl_pass); // URL has a comma.
    delete p;
}

WVTEST_MAIN("Good LDAP Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d3("ldap://dir.carillon.ca/CN=TEST%20RSA%20Signing%20CA"
                 "%2cOU=DEMO%20Certification%20Services%2cO=Carillon%20Information%20Security%20Inc.%2cC=CA?cACertificate;binary?base?objectclass=pkiCA", p, cb);
    while (!d3.is_done())
        WvIStreamList::globallist.runonce();
    WVPASS(dl_pass);
    delete p;
}    

WVTEST_MAIN("No Such entry LDAP Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d3("ldap://chicken/CN=TEST%20RSA%20Signing%20CA1"
                 "%2cOU=DEMO%20Certification%20Services%2cO=Carillon%20Information%20Security%20Inc.%2cC=CA?cACertificate;binary?base?objectclass=pkiCA", p, cb);
    while (!d3.is_done())
        WvIStreamList::globallist.runonce();
    WVFAIL(dl_pass);
    delete p;
}    

/*
WVTEST_MAIN("Too many entries LDAP Download")
{
    WvHttpPool *p = new WvHttpPool();
    WvIStreamList::globallist.append(p, false, "WvHttpPool");

    Downloader d4("ldap://dir.carillon.ca/", p, cb);
    while (!d4.is_done())
        WvIStreamList::globallist.runonce();
    WVFAIL(dl_pass);
}
*/
