#include <wvtest.h>
#include <wvx509mgr.h>

#include "testmethods.t.h"
#include "wvx509path.h"

using namespace boost;


// the NIST tests mostly give this class a good work-out. we only add in a
// quick test for certificates without ski/aki info


WVTEST_MAIN("no ski/aki")
{
    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    strip_ski_aki(ca);
    ca.signcert(ca);
    shared_ptr<WvX509> cacert(new WvX509(ca));

    WvRSAKey rsakey(DEFAULT_KEYLEN);
    WvString certreq = WvX509Mgr::certreq(
        "cn=test.signed.com,dc=signed,dc=com", rsakey);
       
    shared_ptr<WvX509> cert(new WvX509);
    WvString certpem = ca.signreq(certreq);
    cert->decode(WvX509Mgr::CertPEM, certpem);
    strip_ski_aki(*cert);
    ca.signcert(*cert);
   
    WVFAIL(cert->get_ski());
    WVFAIL(cert->get_aki());
    WVFAIL(cacert->get_ski());
    WVFAIL(cacert->get_aki());

    Tester tester;
    tester.add_trusted_cert(cacert);
    tester.add_untrusted_cert(cert);
    WVPASS(tester.validate(wvtcl_escape(ANY_POLICY_OID), 
                           WVX509_SKIP_REVOCATION_CHECK));

    // add a crl to the mix and see what happens
    shared_ptr<WvCRL> crl(new WvCRL(ca));
    tester.add_crl(cert, crl);

    WVPASS(tester.validate(wvtcl_escape(ANY_POLICY_OID), 0));

    crl->addcert(*cert);
    WVPASS(ca.signcrl(*crl));
    WVFAIL(tester.validate(wvtcl_escape(ANY_POLICY_OID), 0));
}
