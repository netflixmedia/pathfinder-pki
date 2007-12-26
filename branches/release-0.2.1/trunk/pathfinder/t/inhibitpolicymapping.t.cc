#include "testmethods.t.h"


WVTEST_MAIN("4.11.1 Invalid inhibitPolicyMapping Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("inhibitPolicyMapping0CACert.crt");
    tester.add_crl("inhibitPolicyMapping0CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping0subCACert.crt");
    tester.add_crl("inhibitPolicyMapping0subCACert.crt",
                   "inhibitPolicyMapping0CACRL.crl");
    tester.add_untrusted_cert("InvalidinhibitPolicyMappingTest1EE.crt");
    tester.add_crl("InvalidinhibitPolicyMappingTest1EE.crt",
                   "inhibitPolicyMapping0subCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.11.2 Valid inhibitPolicyMapping Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");    
    tester.add_untrusted_cert("inhibitPolicyMapping1P12CACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subCACert.crt",
                   "inhibitPolicyMapping1P12CACRL.crl");
    tester.add_untrusted_cert("ValidinhibitPolicyMappingTest2EE.crt");
    tester.add_crl("ValidinhibitPolicyMappingTest2EE.crt",
                   "inhibitPolicyMapping1P12subCACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.11.3 Invalid inhibitPolicyMapping Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");    
    tester.add_untrusted_cert("inhibitPolicyMapping1P12CACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subCACert.crt",
                   "inhibitPolicyMapping1P12CACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subsubCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subsubCACert.crt",
                   "inhibitPolicyMapping1P12subCACRL.crl");
    tester.add_untrusted_cert("InvalidinhibitPolicyMappingTest3EE.crt");
    tester.add_crl("InvalidinhibitPolicyMappingTest3EE.crt",
                   "inhibitPolicyMapping1P12subsubCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.11.4 Valid inhibitPolicyMapping Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");    
    tester.add_untrusted_cert("inhibitPolicyMapping1P12CACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subCACert.crt",
                   "inhibitPolicyMapping1P12CACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subsubCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subsubCACert.crt",
                   "inhibitPolicyMapping1P12subCACRL.crl");
    tester.add_untrusted_cert("ValidinhibitPolicyMappingTest4EE.crt");
    tester.add_crl("ValidinhibitPolicyMappingTest4EE.crt",
                   "inhibitPolicyMapping1P12subsubCACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.11.5 Invalid inhibitPolicyMapping Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("inhibitPolicyMapping5CACert.crt");
    tester.add_crl("inhibitPolicyMapping5CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping5subCACert.crt");
    tester.add_crl("inhibitPolicyMapping5subCACert.crt",
                   "inhibitPolicyMapping5CACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping5subsubCACert.crt");
    tester.add_crl("inhibitPolicyMapping5subsubCACert.crt",
                   "inhibitPolicyMapping5subCACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping5subsubsubCACert.crt");
    tester.add_crl("inhibitPolicyMapping5subsubsubCACert.crt",
                   "inhibitPolicyMapping5subsubCACRL.crl");
    tester.add_untrusted_cert("InvalidinhibitPolicyMappingTest5EE.crt");
    tester.add_crl("InvalidinhibitPolicyMappingTest5EE.crt",
                   "inhibitPolicyMapping5subsubsubCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.11.6 Invalid inhibitPolicyMapping Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12CACert.crt");
    tester.add_crl("inhibitPolicyMapping1P12CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subCAIPM5Cert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subCAIPM5Cert.crt",
                   "inhibitPolicyMapping1P12CACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P12subsubCAIPM5Cert.crt");
    tester.add_crl("inhibitPolicyMapping1P12subsubCAIPM5Cert.crt",
                   "inhibitPolicyMapping1P12subCAIPM5CRL.crl");
    tester.add_untrusted_cert("InvalidinhibitPolicyMappingTest6EE.crt");
    tester.add_crl("InvalidinhibitPolicyMappingTest6EE.crt",
                   "inhibitPolicyMapping1P12subsubCAIPM5CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.11.7 Valid Self-Issued inhibitPolicyMapping Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("inhibitPolicyMapping1P1CACert.crt");
    tester.add_crl("inhibitPolicyMapping1P1CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P1SelfIssuedCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P1SelfIssuedCACert.crt", 
                   "inhibitPolicyMapping1P1CACRL.crl");
    tester.add_untrusted_cert("inhibitPolicyMapping1P1subCACert.crt");
    tester.add_crl("inhibitPolicyMapping1P1subCACert.crt",
                   "inhibitPolicyMapping1P1CACRL.crl");
    tester.add_untrusted_cert("ValidSelfIssuedinhibitPolicyMappingTest7EE.crt");
    tester.add_crl("ValidSelfIssuedinhibitPolicyMappingTest7EE.crt",
                   "inhibitPolicyMapping1P1subCACRL.crl");

    WVPASS(tester.validate());
}
