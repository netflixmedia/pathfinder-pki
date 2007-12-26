#include "testmethods.t.h"


WVTEST_MAIN("4.2.1 Invalid CA notBefore Date Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("BadnotBeforeDateCACert.crt");
    tester.add_crl("BadnotBeforeDateCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidCAnotBeforeDateTest1EE.crt");
    tester.add_crl("InvalidCAnotBeforeDateTest1EE.crt",
                   "BadnotBeforeDateCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.2.2 Invalid EE notBefore Date Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidEEnotBeforeDateTest2EE.crt");
    tester.add_crl("InvalidEEnotBeforeDateTest2EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.2.3 Valid pre2000 UTC notBefore Date Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("Validpre2000UTCnotBeforeDateTest3EE.crt");
    tester.add_crl("Validpre2000UTCnotBeforeDateTest3EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.2.4 Valid GeneralizedTime notBefore Date Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidGeneralizedTimenotBeforeDateTest4EE.crt");
    tester.add_crl("ValidGeneralizedTimenotBeforeDateTest4EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.2.5 Invalid CA notAfter Date Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("BadnotAfterDateCACert.crt");
    tester.add_crl("BadnotAfterDateCACert.crt", "BadnotAfterDateCACRL.crl");
    tester.add_untrusted_cert("InvalidCAnotAfterDateTest5EE.crt");
    tester.add_crl("InvalidCAnotAfterDateTest5EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.2.6 Invalid EE notAfter Date Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidEEnotAfterDateTest6EE.crt");
    tester.add_crl("InvalidEEnotAfterDateTest6EE.crt", "GoodCACRL.crl");

    tester.validate();
    
    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.2.7 Invalid pre2000 UTC EE notAfter Date Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("Invalidpre2000UTCEEnotAfterDateTest7EE.crt");
    tester.add_crl("Invalidpre2000UTCEEnotAfterDateTest7EE.crt", "GoodCACRL.crl");

    tester.validate();
    
    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.2.8 Valid GeneralizedTime notAfter Date Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidGeneralizedTimenotAfterDateTest8EE.crt");
    tester.add_crl("ValidGeneralizedTimenotAfterDateTest8EE.crt", "GoodCACRL.crl");

    tester.validate();
    
    WVPASS(tester.validated);
}
