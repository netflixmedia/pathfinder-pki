#include "testmethods.t.h"


WVTEST_MAIN("4.1.1: Valid Signatures Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidCertificatePathTest1EE.crt");
    tester.add_crl("ValidCertificatePathTest1EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.1.2: Invalid CA Signature Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("BadSignedCACert.crt");
    tester.add_crl("BadSignedCACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidCASignatureTest2EE.crt");
    tester.add_crl("InvalidCASignatureTest2EE.crt", "BadSignedCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.1.3: Invalid EE Signature Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidEESignatureTest3EE.crt");
    tester.add_crl("InvalidEESignatureTest3EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}

#if 0
WVTEST_MAIN("4.1.4: Valid DSA Signatures Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                           "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("DSACACert.crt");
    tester.add_crl("DSACACert.crt", "DSACACRL.crl");
    tester.add_untrusted_cert("ValidDSASignaturesTest4EE.crt");

    tester.validate();

    WVPASS(tester.validated);
}


// this doesn't currently pass because we only recognize crls
// that are signed with rsa keys in wvcrl. probably easy to fix.
WVTEST_MAIN("4.1.5: Valid DSA Parameter Inheritance Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                           "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("DSACACert.crt");
    tester.add_crl("DSACACert.crt", "DSACACRL.crl");
    tester.add_untrusted_cert("DSAParametersInheritedCACert.crt");
    tester.add_crl("DSAParametersInheritedCACert.crt", 
                             "DSAParametersInheritedCACRL.crl");
    tester.add_untrusted_cert("ValidDSAParameterInheritanceTest5EE.crt");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.1.6 Invalid DSA Signature Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                           "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("DSACACert.crt");
    tester.add_crl("DSACACert.crt", "DSACACRL.crl");
    tester.add_untrusted_cert("InvalidDSASignatureTest6EE.crt");

    tester.validate();

    WVFAIL(tester.validated);
}
#endif
