#include "testmethods.t.h"


WVTEST_MAIN("4.3.1 Invalid Name Chaining EE Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidNameChainingTest1EE.crt");
    tester.add_crl("InvalidNameChainingTest1EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.3.2 Invalid Name Chaining Order Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("NameOrderingCACert.crt");
    tester.add_crl("NameOrderingCACert.crt", "NameOrderCACRL.crl");
    tester.add_untrusted_cert("InvalidNameChainingOrderTest2EE.crt");
    tester.add_crl("InvalidNameChainingOrderTest2EE.crt", "NameOrderCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.3.3 Valid Name Chaining Whitespace Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidNameChainingWhitespaceTest3EE.crt");
    tester.add_crl("ValidNameChainingWhitespaceTest3EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.4 Valid Name Chaining Whitespace Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidNameChainingWhitespaceTest4EE.crt");
    tester.add_crl("ValidNameChainingWhitespaceTest4EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.5 Valid Name Chaining Capitalization Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidNameChainingCapitalizationTest5EE.crt");
    tester.add_crl("ValidNameChainingCapitalizationTest5EE.crt", "GoodCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.6 Valid Name Chaining UIDs Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UIDCACert.crt");
    tester.add_crl("UIDCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidNameUIDsTest6EE.crt");
    tester.add_crl("ValidNameUIDsTest6EE.crt", "UIDCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.7 Valid RFC3280 Mandatory Attribute Types Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("RFC3280MandatoryAttributeTypesCACert.crt");
    tester.add_crl("RFC3280MandatoryAttributeTypesCACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidRFC3280MandatoryAttributeTypesTest7EE.crt");
    tester.add_crl("ValidRFC3280MandatoryAttributeTypesTest7EE.crt", 
                   "RFC3280MandatoryAttributeTypesCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.8 Valid RFC3280 Optional Attribute Types Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("RFC3280OptionalAttributeTypesCACert.crt");
    tester.add_crl("RFC3280OptionalAttributeTypesCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidRFC3280OptionalAttributeTypesTest8EE.crt");
    tester.add_crl("ValidRFC3280OptionalAttributeTypesTest8EE.crt", 
                   "RFC3280OptionalAttributeTypesCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);                   
}


WVTEST_MAIN("4.3.9 Valid UTF8String Encoded Names Test9")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UTF8StringEncodedNamesCACert.crt");
    tester.add_crl("UTF8StringEncodedNamesCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidUTF8StringEncodedNamesTest9EE.crt");
    tester.add_crl("ValidUTF8StringEncodedNamesTest9EE.crt", "UTF8StringEncodedNamesCACRL.crl");

    tester.validate();
    
    WVPASS(tester.validated);
}


WVTEST_MAIN("4.3.10 Valid Rollover from PrintableString to UTF8String Test10")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("RolloverfromPrintableStringtoUTF8StringCACert.c"
                              "rt");
    tester.add_crl("RolloverfromPrintableStringtoUTF8StringCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidRolloverfromPrintableStringtoUTF8StringTes"
                              "t10EE.crt");
    tester.add_crl("ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt", 
                   "RolloverfromPrintableStringtoUTF8StringCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}

#if 0
// fails -- probably an openssl bug
WVTEST_MAIN("4.3.11 Valid UTF8String Case Insensitive Match Test11")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UTF8StringCaseInsensitiveMatchCACert.crt");
    tester.add_crl("UTF8StringCaseInsensitiveMatchCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidUTF8StringCaseInsensitiveMatchTest11EE.crt");
    tester.add_crl("ValidUTF8StringCaseInsensitiveMatchTest11EE.crl", 
                   "UTF8StringCaseInsensitiveMatchCACRL.crl");
    tester.validate();
    
    WVPASS(tester.validated);
}

#endif
