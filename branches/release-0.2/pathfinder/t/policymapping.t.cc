#include "testmethods.t.h"


WVTEST_MAIN("4.10.1 Valid Policy Mapping Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("Mapping1to2CACert.crt");
    tester.add_crl("Mapping1to2CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest1EE.crt");
    tester.add_crl("ValidPolicyMappingTest1EE.crt",
                   "Mapping1to2CACRL.crl");

    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVFAIL(tester.validate(NIST_TESTPOLICY_2));
    WVFAIL(tester.validate(ANY_POLICY_OID, 
                           WVX509_INITIAL_POLICY_MAPPING_INHIBIT));
}


WVTEST_MAIN("4.10.2 Invalid Policy Mapping Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("Mapping1to2CACert.crt");
    tester.add_crl("Mapping1to2CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidPolicyMappingTest2EE.crt");
    tester.add_crl("InvalidPolicyMappingTest2EE.crt",
                   "Mapping1to2CACRL.crl");

    WVFAIL(tester.validate());
    WVFAIL(tester.validate(ANY_POLICY_OID, 
                           WVX509_INITIAL_POLICY_MAPPING_INHIBIT));
}


WVTEST_MAIN("4.10.3 Valid Policy Mapping Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P12Mapping1to3CACert.crt");
    tester.add_crl("P12Mapping1to3CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("P12Mapping1to3subCACert.crt");
    tester.add_crl("P12Mapping1to3subCACert.crt",
                   "P12Mapping1to3CACRL.crl");
    tester.add_untrusted_cert("P12Mapping1to3subsubCACert.crt");
    tester.add_crl("P12Mapping1to3subsubCACert.crt", 
                   "P12Mapping1to3subCACRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest3EE.crt");
    tester.add_crl("ValidPolicyMappingTest3EE.crt", 
                   "P12Mapping1to3subsubCACRL.crl");
    
    WVFAIL(tester.validate(NIST_TESTPOLICY_1));
    WVPASS(tester.validate(NIST_TESTPOLICY_2));
}


WVTEST_MAIN("4.10.4 Invalid Policy Mapping Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P12Mapping1to3CACert.crt");
    tester.add_crl("P12Mapping1to3CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("P12Mapping1to3subCACert.crt");
    tester.add_crl("P12Mapping1to3subCACert.crt",
                   "P12Mapping1to3CACRL.crl");
    tester.add_untrusted_cert("P12Mapping1to3subsubCACert.crt");
    tester.add_crl("P12Mapping1to3subsubCACert.crt", 
                   "P12Mapping1to3subCACRL.crl");
    tester.add_untrusted_cert("InvalidPolicyMappingTest4EE.crt");
    tester.add_crl("InvalidPolicyMappingTest4EE.crt", 
                   "P12Mapping1to3subsubCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.10.5 Valid Policy Mapping Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P1Mapping1to234CACert.crt");
    tester.add_crl("P1Mapping1to234CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("P1Mapping1to234subCACert.crt");
    tester.add_crl("P1Mapping1to234subCACert.crt",
                   "P1Mapping1to234CACRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest5EE.crt");
    tester.add_crl("ValidPolicyMappingTest5EE.crt", 
                   "P1Mapping1to234subCACRL.crl");

    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVFAIL(tester.validate(NIST_TESTPOLICY_6));
}


WVTEST_MAIN("4.10.6 Valid Policy Mapping Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P1Mapping1to234CACert.crt");
    tester.add_crl("P1Mapping1to234CACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("P1Mapping1to234subCACert.crt");
    tester.add_crl("P1Mapping1to234subCACert.crt",
                   "P1Mapping1to234CACRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest6EE.crt");
    tester.add_crl("ValidPolicyMappingTest6EE.crt", 
                   "P1Mapping1to234subCACRL.crl");

    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVFAIL(tester.validate(NIST_TESTPOLICY_6));
}


WVTEST_MAIN("4.10.7 Invalid Mapping From anyPolicy Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("MappingFromanyPolicyCACert.crt");
    tester.add_crl("MappingFromanyPolicyCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidMappingFromanyPolicyTest7EE.crt");
    tester.add_crl("InvalidMappingFromanyPolicyTest7EE.crt",
                   "MappingFromanyPolicyCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.10.8 Invalid Mapping To anyPolicy Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("MappingToanyPolicyCACert.crt");
    tester.add_crl("MappingToanyPolicyCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidMappingToanyPolicyTest8EE.crt");
    tester.add_crl("InvalidMappingToanyPolicyTest8EE.crt", 
                   "MappingToanyPolicyCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.10.9 Valid Policy Mapping Test9")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("PanyPolicyMapping1to2CACert.crt");
    tester.add_crl("PanyPolicyMapping1to2CACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest9EE.crt");
    tester.add_crl("ValidPolicyMappingTest9EE.crt",
                   "PanyPolicyMapping1to2CACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.10.10 Invalid Policy Mapping Test10")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodsubCAPanyPolicyMapping1to2CACert.crt");
    tester.add_crl("GoodsubCAPanyPolicyMapping1to2CACert.crt",
                   "GoodCACRL.crl");
    tester.add_untrusted_cert("InvalidPolicyMappingTest10EE.crt");
    tester.add_crl("InvalidPolicyMappingTest10EE.crt", 
                   "GoodsubCAPanyPolicyMapping1to2CACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.10.11 Valid Policy Mapping Test11")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodsubCAPanyPolicyMapping1to2CACert.crt");
    tester.add_crl("GoodsubCAPanyPolicyMapping1to2CACert.crt",
                   "GoodCACRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest11EE.crt");
    tester.add_crl("ValidPolicyMappingTest11EE.crt", 
                   "GoodsubCAPanyPolicyMapping1to2CACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.10.12 Valid Policy Mapping Test12")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P12Mapping1to3CACert.crt");
    tester.add_crl("P12Mapping1to3CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest12EE.crt");
    tester.add_crl("ValidPolicyMappingTest12EE.crt",
                   "P12Mapping1to3CACRL.crl");

    WVPASS(tester.validate());
    WVPASS(tester.validate(NIST_TESTPOLICY_1));
    WVPASS(tester.validate(NIST_TESTPOLICY_2));
}


WVTEST_MAIN("4.10.13 Valid Policy Mapping Test13")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P1anyPolicyMapping1to2CACert.crt");
    tester.add_crl("P1anyPolicyMapping1to2CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest13EE.crt");
    tester.add_crl("ValidPolicyMappingTest13EE.crt",
                   "P1anyPolicyMapping1to2CACRL.crl");
    
    WVPASS(tester.validate());
}


WVTEST_MAIN("4.10.14 Valid Policy Mapping Test14")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("P1anyPolicyMapping1to2CACert.crt");
    tester.add_crl("P1anyPolicyMapping1to2CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidPolicyMappingTest14EE.crt");
    tester.add_crl("ValidPolicyMappingTest14EE.crt",
                   "P1anyPolicyMapping1to2CACRL.crl");
    
    WVPASS(tester.validate());
}

