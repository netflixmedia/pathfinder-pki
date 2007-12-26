#include "testmethods.t.h"


WVTEST_MAIN("4.4.1 Missing CRL Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("NoCRLCACert.crt");
    tester.add_crl("NoCRLCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidMissingCRLTest1EE.crt");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.4.2 Invalid Revoked CA Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("RevokedsubCACert.crt");
    tester.add_crl("RevokedsubCACert.crt", "GoodCACRL.crl");
    tester.add_untrusted_cert("InvalidRevokedCATest2EE.crt");
    tester.add_crl("InvalidRevokedCATest2EE.crt", "RevokedsubCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.4.3 Invalid Revoked EE Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GoodCACert.crt");
    tester.add_crl("GoodCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidRevokedEETest3EE.crt");
    tester.add_crl("InvalidRevokedEETest3EE.crt", "GoodCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.4 Invalid Bad CRL Signature Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("BadCRLSignatureCACert.crt");
    tester.add_crl("BadCRLSignatureCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidBadCRLSignatureTest4EE.crt");
    tester.add_crl("InvalidBadCRLSignatureTest4EE.crt", 
                   "BadCRLSignatureCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.5 Invalid Bad CRL Issuer Name Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("BadCRLIssuerNameCACert.crt");
    tester.add_crl("BadCRLIssuerNameCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidBadCRLIssuerNameTest5EE.crt");
    tester.add_crl("InvalidBadCRLIssuerNameTest5EE.crt", 
                   "BadCRLIssuerNameCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.6 Invalid Wrong CRL Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("WrongCRLCACert.crt");
    tester.add_crl("WrongCRLCACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidWrongCRLTest6EE.crt");
    tester.add_crl("InvalidWrongCRLTest6EE.crt", "WrongCRLCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.7 Valid Two CRLs Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("TwoCRLsCACert.crt");
    tester.add_crl("TwoCRLsCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidTwoCRLsTest7EE.crt");
    tester.add_crl("ValidTwoCRLsTest7EE.crt", "TwoCRLsCABadCRL.crl"); 
    tester.add_crl("ValidTwoCRLsTest7EE.crt", "TwoCRLsCAGoodCRL.crl"); 

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.4.8 Invalid Unknown CRL Entry Extension Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UnknownCRLEntryExtensionCACert.crt");
    tester.add_crl("UnknownCRLEntryExtensionCACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidUnknownCRLEntryExtensionTest8EE.crt");
    tester.add_crl("InvalidUnknownCRLEntryExtensionTest8EE.crt", 
                   "UnknownCRLEntryExtensionCACRL.crl");

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.9 Invalid Unknown CRL Extension Test9")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UnknownCRLExtensionCACert.crt");
    tester.add_crl("UnknownCRLExtensionCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidUnknownCRLExtensionTest9EE.crt");
    tester.add_crl("InvalidUnknownCRLExtensionTest9EE.crt", 
                   "UnknownCRLExtensionCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.10 Invalid Unknown CRL Extension Test10")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("UnknownCRLExtensionCACert.crt");
    tester.add_crl("UnknownCRLExtensionCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidUnknownCRLExtensionTest10EE.crt");
    tester.add_crl("InvalidUnknownCRLExtensionTest10EE.crt", 
                   "UnknownCRLExtensionCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.11 Invalid Old CRL nextUpdate Test11")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("OldCRLnextUpdateCACert.crt");
    tester.add_crl("OldCRLnextUpdateCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidOldCRLnextUpdateTest11EE.crt");
    tester.add_crl("InvalidOldCRLnextUpdateTest11EE.crt", 
                   "OldCRLnextUpdateCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.12 Invalid pre2000 CRL nextUpdate Test12")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pre2000CRLnextUpdateCACert.crt");
    tester.add_crl("pre2000CRLnextUpdateCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("Invalidpre2000CRLnextUpdateTest12EE.crt");
    tester.add_crl("Invalidpre2000CRLnextUpdateTest12EE.crt", 
                   "pre2000CRLnextUpdateCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.13 Valid GeneralizedTime CRL nextUpdate Test13")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("GeneralizedTimeCRLnextUpdateCACert.crt");
    tester.add_crl("GeneralizedTimeCRLnextUpdateCACert.crt", 
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidGeneralizedTimeCRLnextUpdateTest13EE.crt");
    tester.add_crl("ValidGeneralizedTimeCRLnextUpdateTest13EE.crt", 
                   "GeneralizedTimeCRLnextUpdateCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);  
}


WVTEST_MAIN("4.4.14 Valid Negative Serial Number Test14")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("NegativeSerialNumberCACert.crt");
    tester.add_crl("NegativeSerialNumberCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidNegativeSerialNumberTest14EE.crt");
    tester.add_crl("ValidNegativeSerialNumberTest14EE.crt", 
                   "NegativeSerialNumberCACRL.crl");

    tester.validate();

    WVPASS(tester.validated);
}


WVTEST_MAIN("4.4.15 Invalid Negative Serial Number Test15")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("NegativeSerialNumberCACert.crt");
    tester.add_crl("NegativeSerialNumberCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidNegativeSerialNumberTest15EE.crt");
    tester.add_crl("InvalidNegativeSerialNumberTest15EE.crt", 
                   "NegativeSerialNumberCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.16 Valid Long Serial Number Test16")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("LongSerialNumberCACert.crt");
    tester.add_crl("LongSerialNumberCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidLongSerialNumberTest16EE.crt");
    tester.add_crl("ValidLongSerialNumberTest16EE.crt", 
                   "LongSerialNumberCACRL.crl"); 

    tester.validate();

    WVPASS(tester.validated);  
}


WVTEST_MAIN("4.4.17 Valid Long Serial Number Test17")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("LongSerialNumberCACert.crt");
    tester.add_crl("LongSerialNumberCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidLongSerialNumberTest17EE.crt");
    tester.add_crl("ValidLongSerialNumberTest17EE.crt", 
                   "LongSerialNumberCACRL.crl"); 

    tester.validate();

    WVPASS(tester.validated);  
}


WVTEST_MAIN("4.4.18 Invalid Long Serial Number Test18")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("LongSerialNumberCACert.crt");
    tester.add_crl("LongSerialNumberCACert.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidLongSerialNumberTest18EE.crt");
    tester.add_crl("InvalidLongSerialNumberTest18EE.crt", 
                   "LongSerialNumberCACRL.crl"); 

    tester.validate();

    WVFAIL(tester.validated);
}


WVTEST_MAIN("4.4.19 Valid Separate Certificate and CRL Keys Test19")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("SeparateCertificateandCRLKeysCertificateSigningCACert.crt");    
    tester.add_crl("SeparateCertificateandCRLKeysCertificateSigningCACert.crt",
                   "TrustAnchorRootCRL.crl"); 
    tester.add_intermediate_cert("SeparateCertificateandCRLKeysCRLSigningCert.crt");
    tester.add_crl("SeparateCertificateandCRLKeysCRLSigningCert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidSeparateCertificateandCRLKeysTest19EE.crt");
    tester.add_crl("ValidSeparateCertificateandCRLKeysTest19EE.crt",
                   "SeparateCertificateandCRLKeysCRL.crl");

    tester.validate();

    WVPASS(tester.validated);  
}


WVTEST_MAIN("4.4.20 Invalid Separate Certificate and CRL Keys Test20")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_crl("TrustAnchorRootCertificate.crt", "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("SeparateCertificateandCRLKeysCertificateSigningCACert.crt");    
    tester.add_crl("SeparateCertificateandCRLKeysCertificateSigningCACert.crt",
                   "TrustAnchorRootCRL.crl"); 
    tester.add_intermediate_cert("SeparateCertificateandCRLKeysCRLSigningCert.crt");
    tester.add_crl("SeparateCertificateandCRLKeysCA2CRLSigningCert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidSeparateCertificateandCRLKeysTest20EE.crt");
    tester.add_crl("InvalidSeparateCertificateandCRLKeysTest20EE.crt",
                   "SeparateCertificateandCRLKeysCRL.crl");

    tester.validate();

    WVFAIL(tester.validated);  
}


WVTEST_MAIN("4.4.21 Invalid Separate Certificate and CRL Keys Test21")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("SeparateCertificateandCRLKeysCA2CertificateSigningCACert.crt");
    tester.add_crl("SeparateCertificateandCRLKeysCA2CertificateSigningCACert.crt",
                   "TrustAnchorRootCRL.crl"); 
    tester.add_intermediate_cert("SeparateCertificateandCRLKeysCA2CRLSigningCert.crt");
    tester.add_crl("SeparateCertificateandCRLKeysCA2CRLSigningCert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidSeparateCertificateandCRLKeysTest21EE.crt");
    tester.add_crl("InvalidSeparateCertificateandCRLKeysTest21EE.crt",
                   "SeparateCertificateandCRLKeysCA2CRL.crl");

    tester.validate();

    WVFAIL(tester.validated);  
}
