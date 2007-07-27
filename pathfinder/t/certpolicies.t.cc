#include "testmethods.t.h"


WVTEST_MAIN("4.8.1 All Certificates Same Policy Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidCertificatePathTest1EE.crt");
    tester.add_crl("ValidCertificatePathTest1EE.crt", "GoodCACRL.crl");

    WVPASS(tester.validate());
    WVPASS(tester.validate(NIST_TESTPOLICY_1, WVX509_INITIAL_EXPLICIT_POLICY));
    WVFAIL(tester.validate(NIST_TESTPOLICY_2, WVX509_INITIAL_EXPLICIT_POLICY));
    WVPASS(tester.validate(NIST_TESTPOLICY_1 " " NIST_TESTPOLICY_2, 
                           WVX509_INITIAL_EXPLICIT_POLICY));
}


WVTEST_MAIN("4.8.2 All Certificates No Policies Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("NoPoliciesCACert.crt");
    tester.add_crl("NoPoliciesCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("AllCertificatesNoPoliciesTest2EE.crt");
    tester.add_crl("AllCertificatesNoPoliciesTest2EE.crt", 
                   "NoPoliciesCACRL.crl");

    WVPASS(tester.validate()); 
    WVFAIL(tester.validate(ANY_POLICY_OID, WVX509_INITIAL_EXPLICIT_POLICY));
}


WVTEST_MAIN("4.8.3 Different Policies Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP2subCACert.crt");
    tester.add_crl("PoliciesP2subCACert.crt", "GoodCACRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest3EE.crt");
    tester.add_crl("DifferentPoliciesTest3EE.crt", "PoliciesP2subCACRL.crl");

    WVPASS(tester.validate());
    WVFAIL(tester.validate(ANY_POLICY_OID, WVX509_INITIAL_EXPLICIT_POLICY));
    WVFAIL(tester.validate(NIST_TESTPOLICY_1 " " NIST_TESTPOLICY_2, 
                           WVX509_INITIAL_EXPLICIT_POLICY));

}


WVTEST_MAIN("4.8.4 Different Policies Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodsubCACert.crt");
    tester.add_crl("GoodsubCACert.crt", "GoodCACRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest4EE.crt");
    tester.add_crl("DifferentPoliciesTest4EE.crt", "GoodsubCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.8.5 Different Policies Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP2subCA2Cert.crt");
    tester.add_crl("PoliciesP2subCA2Cert.crt", "GoodCACRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest5EE.crt");
    tester.add_crl("DifferentPoliciesTest5EE.crt", "PoliciesP2subCA2CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.8.6 Overlapping Policies Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP1234CACert.crt");
    tester.add_crl("PoliciesP1234CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP1234subCAP123Cert.crt");
    tester.add_crl("PoliciesP1234subCAP123Cert.crt", 
                   "PoliciesP1234CACRL.crl");
    tester.add_untrusted_cert("PoliciesP1234subsubCAP123P12Cert.crt");
    tester.add_crl("PoliciesP1234subsubCAP123P12Cert.crt", 
                   "PoliciesP1234subCAP123CRL.crl");
    tester.add_untrusted_cert("OverlappingPoliciesTest6EE.crt");
    tester.add_crl("OverlappingPoliciesTest6EE.crt",
                   "PoliciesP1234subsubCAP123P12CRL.crl");

    WVPASS(tester.validate());
    WVPASS(tester.validate(NIST_TESTPOLICY_1, WVX509_INITIAL_EXPLICIT_POLICY));
    WVFAIL(tester.validate(NIST_TESTPOLICY_2, WVX509_INITIAL_EXPLICIT_POLICY));
}


WVTEST_MAIN("4.8.7 Different Policies Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP123CACert.crt");
    tester.add_crl("PoliciesP123CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP123subCAP12Cert.crt");
    tester.add_crl("PoliciesP123subCAP12Cert.crt", 
                   "PoliciesP123CACRL.crl");
    tester.add_untrusted_cert("PoliciesP123subsubCAP12P1Cert.crt");
    tester.add_crl("PoliciesP123subsubCAP12P1Cert.crt", 
                   "PoliciesP123subCAP12CRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest7EE.crt");
    tester.add_crl("DifferentPoliciesTest7EE.crt",
                   "PoliciesP123subsubCAP12P1CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.8.8 Different Policies Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP12CACert.crt");
    tester.add_crl("PoliciesP12CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP12subCAP1Cert.crt");
    tester.add_crl("PoliciesP12subCAP1Cert.crt", "PoliciesP12CACRL.crl");
    tester.add_untrusted_cert("PoliciesP12subsubCAP1P2Cert.crt");
    tester.add_crl("PoliciesP12subsubCAP1P2Cert.crt", 
                   "PoliciesP12subCAP1CRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest8EE.crt");
    tester.add_crl("DifferentPoliciesTest8EE.crt",
                   "PoliciesP12subsubCAP1P2CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.8.9 Different Policies Test9")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP123CACert.crt");
    tester.add_crl("PoliciesP123CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("PoliciesP123subCAP12Cert.crt");
    tester.add_crl("PoliciesP123subCAP12Cert.crt", 
                   "PoliciesP123CACRL.crl");
    tester.add_untrusted_cert("PoliciesP123subsubCAP12P2Cert.crt");
    tester.add_crl("PoliciesP123subsubCAP12P2Cert.crt",
                   "PoliciesP123subCAP12CRL.crl");
    tester.add_untrusted_cert("PoliciesP123subsubsubCAP12P2P1Cert.crt");
    tester.add_crl("PoliciesP123subsubsubCAP12P2P1Cert.crt",
                   "PoliciesP123subsubCAP2P2CRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest9EE.crt");
    tester.add_crl("DifferentPoliciesTest9EE.crt",
                   "PoliciesP123subsubsubCAP12P2P1CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.8.10 All Certificates Same Policies Test10")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP12CACert.crt");
    tester.add_crl("PoliciesP12CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("AllCertificatesSamePoliciesTest10EE.crt");
    tester.add_crl("AllCertificatesSamePoliciesTest10EE.crt",
                   "PoliciesP12CACRL.crl");

    WVPASS(tester.validate());
    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVPASS(tester.validate(NIST_TESTPOLICY_2));    
}


WVTEST_MAIN("4.8.11 All Certificates AnyPolicy Test11")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("anyPolicyCACert.crt");
    tester.add_crl("anyPolicyCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("AllCertificatesanyPolicyTest11EE.crt");
    tester.add_crl("AllCertificatesanyPolicyTest11EE.crt",
                   "anyPolicyCACRL.crl");

    WVPASS(tester.validate());
    WVPASS(tester.validate(NIST_TESTPOLICY_1));
}


WVTEST_MAIN("4.8.12 Different Policies Test12")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP3CACert.crt");
    tester.add_crl("PoliciesP3CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("DifferentPoliciesTest12EE.crt");
    tester.add_crl("DifferentPoliciesTest12EE.crt",
                   "PoliciesP3CACRL.crl");

    WVFAIL(tester.validate(ANY_POLICY_OID));
}


WVTEST_MAIN("4.8.13 All Certificates Same Policies Test13")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PoliciesP123CACert.crt");
    tester.add_crl("PoliciesP123CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("AllCertificatesSamePoliciesTest13EE.crt");
    tester.add_crl("AllCertificatesSamePoliciesTest13EE.crt",
                   "PoliciesP123CACRL.crl");
    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVPASS(tester.validate(NIST_TESTPOLICY_2));
    WVPASS(tester.validate(NIST_TESTPOLICY_3));

}


WVTEST_MAIN("4.8.14 AnyPolicy Test14")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("anyPolicyCACert.crt");
    tester.add_crl("anyPolicyCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("AnyPolicyTest14EE.crt");
    tester.add_crl("AnyPolicyTest14EE.crt",
                   "anyPolicyCACRL.crl");

    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVFAIL(tester.validate(NIST_TESTPOLICY_2));
}
