#include "testmethods.t.h"


WVTEST_MAIN("4.6.1 Invalid Missing basicConstraints Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("MissingbasicConstraintsCACert.crt");
    tester.add_crl("MissingbasicConstraintsCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidMissingbasicConstraintsTest1EE.crt");
    tester.add_crl("InvalidMissingbasicConstraintsTest1EE.crt",
                   "MissingbasicConstraintsCACRL.crl");
    
    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.2 Invalid cA False Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("basicConstraintsCriticalcAFalseCACert.crt");
    tester.add_crl("basicConstraintsCriticalcAFalseCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidcAFalseTest2EE.crt");
    tester.add_crl("InvalidcAFalseTest2EE.crt",
                   "basicConstraintsCriticalcAFalseCACRL.crl");
    
    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.3 Invalid cA False Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("basicConstraintsNotCriticalcAFalseCACert.crt");
    tester.add_crl("basicConstraintsNotCriticalcAFalseCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("InvalidcAFalseTest3EE.crt");
    tester.add_crl("InvalidcAFalseTest3EE.crt",
                   "basicConstraintsNotCriticalcAFalseCACRL.crl");
    
    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.4 Valid basicConstraints Not Critical Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("basicConstraintsNotCriticalCACert.crt");
    tester.add_crl("basicConstraintsNotCriticalCACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidbasicConstraintsNotCriticalTest4EE.crt");
    tester.add_crl("ValidbasicConstraintsNotCriticalTest4EE.crt",
                   "basicConstraintsNotCriticalCACRL.crl");
    
    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.5 Invalid pathLenConstraint Test5")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint0subCACert.crt");
    tester.add_crl("pathLenConstraint0subCACert.crt",
                   "pathLenConstraint0CACRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest5EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest5EE.crt",
                   "pathLenConstraint0subCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.6 Invalid pathLenConstraint Test6")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint0subCACert.crt");
    tester.add_crl("pathLenConstraint0subCACert.crt",
                   "pathLenConstraint0CACRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest6EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest6EE.crt",
                   "pathLenConstraint0subCACRL.crl");

    WVFAIL(tester.validate());
}

WVTEST_MAIN("4.6.7 Valid pathLenConstraint Test7")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidpathLenConstraintTest7EE.crt");
    tester.add_crl("ValidpathLenConstraintTest7EE.crt",
                   "pathLenConstraint0CACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.8 Valid pathLenConstraint Test8")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("ValidpathLenConstraintTest8EE.crt");
    tester.add_crl("ValidpathLenConstraintTest8EE.crt",
                   "pathLenConstraint0CACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.9 Invalid pathLenConstraint Test9")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA0Cert.crt");
    tester.add_crl("pathLenConstraint6subCA0Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA00Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA00Cert.crt",
                   "pathLenConstraint6subCA0CRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest9EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest9EE.crt",
                   "pathLenConstraint6subsubCA00CRL.crl");
    
    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.10 Invalid pathLenConstraint Test10")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA0Cert.crt");
    tester.add_crl("pathLenConstraint6subCA0Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA00Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA00Cert.crt",
                   "pathLenConstraint6subCA0CRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest10EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest10EE.crt",
                   "pathLenConstraint6subsubCA00CRL.crl");
    
    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.11 Invalid pathLenConstraint Test11")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA1Cert.crt");
    tester.add_crl("pathLenConstraint6subCA1Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA11Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA11Cert.crt",
                   "pathLenConstraint6subCA1CRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubsubCA11XCert.crt");
    tester.add_crl("pathLenConstraint6subsubsubCA11XCert.crt",
                   "pathLenConstraint6subsubCA11CRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest11EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest11EE.crt", 
                   "pathLenConstraint6subsubsubCA11XCRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.12 Invalid pathLenConstraint Test12")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA1Cert.crt");
    tester.add_crl("pathLenConstraint6subCA1Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA11Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA11Cert.crt",
                   "pathLenConstraint6subCA1CRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubsubCA11XCert.crt");
    tester.add_crl("pathLenConstraint6subsubsubCA11XCert.crt",
                   "pathLenConstraint6subsubCA11CRL.crl");
    tester.add_untrusted_cert("InvalidpathLenConstraintTest12EE.crt");
    tester.add_crl("InvalidpathLenConstraintTest12EE.crt", 
                   "pathLenConstraint6subsubsubCA11XCRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.13 Valid pathLenConstraint Test13")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA4Cert.crt");
    tester.add_crl("pathLenConstraint6subCA4Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA41Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA41Cert.crt",
                   "pathLenConstraint6subCA4CRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubsubCA41XCert.crt");
    tester.add_crl("pathLenConstraint6subsubsubCA41XCert.crt",
                   "pathLenConstraint6subsubCA41CRL.crl");
    tester.add_untrusted_cert("ValidpathLenConstraintTest13EE.crt");
    tester.add_crl("ValidpathLenConstraintTest13EE.crt", 
                   "pathLenConstraint6subsubsubCA41XCRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.14 Valid pathLenConstraint Test14")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint6CACert.crt");
    tester.add_crl("pathLenConstraint6CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subCA4Cert.crt");
    tester.add_crl("pathLenConstraint6subCA4Cert.crt",
                   "pathLenConstraint6CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubCA41Cert.crt");
    tester.add_crl("pathLenConstraint6subsubCA41Cert.crt",
                   "pathLenConstraint6subCA4CRL.crl");
    tester.add_untrusted_cert("pathLenConstraint6subsubsubCA41XCert.crt");
    tester.add_crl("pathLenConstraint6subsubsubCA41XCert.crt",
                   "pathLenConstraint6subsubCA41CRL.crl");
    tester.add_untrusted_cert("ValidpathLenConstraintTest14EE.crt");
    tester.add_crl("ValidpathLenConstraintTest14EE.crt", 
                   "pathLenConstraint6subsubsubCA41XCRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.15 Valid Self-Issued pathLenConstraint Test15")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint0SelfIssuedCACert.crt");
    tester.add_crl("pathLenConstraint0SelfIssuedCACert.crt",
                   "pathLenConstraint0CACRL.crl");
    tester.add_untrusted_cert("ValidSelfIssuedpathLenConstraintTest15EE.crt");
    tester.add_crl("ValidSelfIssuedpathLenConstraintTest15EE.crt",
                   "pathLenConstraint0CACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.6.16 Invalid Self-Issued pathLenConstraint Test16")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint0CACert.crt");
    tester.add_crl("pathLenConstraint0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint0SelfIssuedCACert.crt");
    tester.add_crl("pathLenConstraint0SelfIssuedCACert.crt",
                   "pathLenConstraint0CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint0subCA2Cert.crt");
    tester.add_crl("pathLenConstraint0subCA2Cert.crt",
                   "pathLenConstraint0CACRL.crl");
    tester.add_untrusted_cert("InvalidSelfIssuedpathLenConstraintTest16EE.crt");
    tester.add_crl("InvalidSelfIssuedpathLenConstraintTest16EE.crt",
                   "pathLenConstraint0subCA2CRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.6.17 Valid Self-Issued pathLenConstraint Test17")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("pathLenConstraint1CACert.crt");
    tester.add_crl("pathLenConstraint1CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("pathLenConstraint1SelfIssuedCACert.crt");
    tester.add_crl("pathLenConstraint1SelfIssuedCACert.crt",
                   "pathLenConstraint1CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint1subCACert.crt");
    tester.add_crl("pathLenConstraint1subCACert.crt",
                   "pathLenConstraint1CACRL.crl");
    tester.add_untrusted_cert("pathLenConstraint1SelfIssuedsubCACert.crt");
    tester.add_crl("pathLenConstraint1SelfIssuedsubCACert.crt",
                   "pathLenConstraint1subCACRL.crl");
    tester.add_untrusted_cert("ValidSelfIssuedpathLenConstraintTest17EE.crt");
    tester.add_crl("ValidSelfIssuedpathLenConstraintTest17EE.crt",
                   "pathLenConstraint1subCACRL.crl");
    
    WVPASS(tester.validate());   
}
