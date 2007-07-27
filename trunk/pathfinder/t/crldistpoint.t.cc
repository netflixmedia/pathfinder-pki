#include "testmethods.t.h"

// basically none of the tests in section 4.14 will validate properly. A small 
// selection of tests is provided to ensure that we fail gracefully given our
// current limitations


WVTEST_MAIN("4.14.1 Valid distributionPoint Test1")
{
    // this path should validate, but we don't yet handle the 
    // issuingDistributionPoint extension in WvCRL (due to a limitation in 
    // OpenSSL 0.9.8)

    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("distributionPoint1CACert.crt");
    tester.add_crl("distributionPoint1CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValiddistributionPointTest1EE.crt");
    tester.add_crl("ValiddistributionPointTest1EE.crt",
                    "distributionPoint1CACRL.crl");

    WVFAIL(tester.validate());
} 


WVTEST_MAIN("4.14.2 Invalid distributionPoint Test2")
{
    // this path shouldn't validate, but not for the reason it currently does
    // (see the comment in 4.14.1)

    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("distributionPoint1CACert.crt");
    tester.add_crl("distributionPoint1CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvaliddistributionPointTest2EE.crt");
    tester.add_crl("InvaliddistributionPointTest2EE.crt",
                    "distributionPoint1CACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.14.3 Invalid distributionPoint Test3")
{
    // this path shouldn't validate, but not for the reason it currently does
    // (see the comment in 4.14.1)

    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("distributionPoint1CACert.crt");
    tester.add_crl("distributionPoint1CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvaliddistributionPointTest3EE.crt");
    tester.add_crl("InvaliddistributionPointTest3EE.crt",
                    "distributionPoint1CACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.14.4 Valid distributionPoint Test4")
{
    // this path should validate, but doesn't yet (see the comment in 4.14.1)

    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("distributionPoint1CACert.crt");
    tester.add_crl("distributionPoint1CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValiddistributionPointTest4EE.crt");
    tester.add_crl("ValiddistributionPointTest4EE.crt",
                    "distributionPoint1CACRL.crl");

    WVFAIL(tester.validate());

}
