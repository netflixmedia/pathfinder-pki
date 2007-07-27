#include "testmethods.t.h"


WVTEST_MAIN("4.9.1 Valid RequireExplicitPolicy Test1")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("requireExplicitPolicy10CACert.crt");
    tester.add_crl("requireExplicitPolicy10CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy10subCACert.crt");
    tester.add_crl("requireExplicitPolicy10subCACert.crt",
                   "requireExplicitPolicy10CACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy10subsubCACert.crt");
    tester.add_crl("requireExplicitPolicy10subsubCACert.crt",
                   "requireExplicitPolicy10subCACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy10subsubsubCACert.crt");
    tester.add_crl("requireExplicitPolicy10subsubsubCACert.crt",
                   "requireExplicitPolicy10subsubCACRL.crl");
    tester.add_untrusted_cert("ValidrequireExplicitPolicyTest1EE.crt");
    tester.add_crl("ValidrequireExplicitPolicyTest1EE.crt",
                   "requireExplicitPolicy10subsubsubCACRL.crl");

    WVPASS(tester.validate());

}


WVTEST_MAIN("4.9.2 Valid RequireExplicitPolicy Test2")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("requireExplicitPolicy5CACert.crt");
    tester.add_crl("requireExplicitPolicy5CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy5subCACert.crt");
    tester.add_crl("requireExplicitPolicy5subCACert.crt",
                   "requireExplicitPolicy5CACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy5subsubCACert.crt");
    tester.add_crl("requireExplicitPolicy5subsubCACert.crt",
                   "requireExplicitPolicy5subCACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy5subsubsubCACert.crt");
    tester.add_crl("requireExplicitPolicy5subsubsubCACert.crt",
                   "requireExplicitPolicy5subsubCACRL.crl");
    tester.add_untrusted_cert("ValidrequireExplicitPolicyTest2EE.crt");
    tester.add_crl("ValidrequireExplicitPolicyTest2EE.crt",
                   "requireExplicitPolicy5subsubsubCACRL.crl");

    WVPASS(tester.validate());
}


WVTEST_MAIN("4.9.3 Invalid RequireExplicitPolicy Test3")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("requireExplicitPolicy4CACert.crt");
    tester.add_crl("requireExplicitPolicy4CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy4subCACert.crt");
    tester.add_crl("requireExplicitPolicy4subCACert.crt",
                   "requireExplicitPolicy4CACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy4subsubCACert.crt");
    tester.add_crl("requireExplicitPolicy4subsubCACert.crt",
                   "requireExplicitPolicy4subCACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy4subsubsubCACert.crt");
    tester.add_crl("requireExplicitPolicy4subsubsubCACert.crt",
                   "requireExplicitPolicy4subsubCACRL.crl");
    tester.add_untrusted_cert("InvalidrequireExplicitPolicyTest3EE.crt");
    tester.add_crl("InvalidrequireExplicitPolicyTest3EE.crt",
                   "requireExplicitPolicy4subsubsubCACRL.crl");

    WVFAIL(tester.validate());
}


WVTEST_MAIN("4.9.4 Valid RequireExplicitPolicy Test4")
{
    Tester tester;
    tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
    tester.add_untrusted_cert("requireExplicitPolicy0CACert.crt");
    tester.add_crl("requireExplicitPolicy0CACert.crt",
                   "TrustAnchorRootCRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy0subCACert.crt");
    tester.add_crl("requireExplicitPolicy0subCACert.crt",
                   "requireExplicitPolicy0CACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy0subsubCACert.crt");
    tester.add_crl("requireExplicitPolicy0subsubCACert.crt",
                   "requireExplicitPolicy0subCACRL.crl");
    tester.add_untrusted_cert("requireExplicitPolicy0subsubsubCACert.crt");
    tester.add_crl("requireExplicitPolicy0subsubsubCACert.crt",
                   "requireExplicitPolicy0subsubCACRL.crl");
     tester.add_untrusted_cert("ValidrequireExplicitPolicyTest4EE.crt");
     tester.add_crl("ValidrequireExplicitPolicyTest4EE.crt",
                   "requireExplicitPolicy0subsubsubCACRL.crl");

    WVPASS(tester.validate());

}


WVTEST_MAIN("4.9.5 Invalid RequireExplicitPolicy Test5")
{
   Tester tester;
   tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
   tester.add_untrusted_cert("requireExplicitPolicy7CACert.crt");
   tester.add_crl("requireExplicitPolicy7CACert.crt",
                  "TrustAnchorRootCRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy7subCARE2Cert.crt");
   tester.add_crl("requireExplicitPolicy7subCARE2Cert.crt",
                  "requireExplicitPolicy7CACRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy7subsubCARE2RE4Cert.crt");
   tester.add_crl("requireExplicitPolicy7subsubCARE2RE4Cert.crt",
                  "requireExplicitPolicy7subCARE2CRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy7subsubsubCARE2RE4Cert.crt");
   tester.add_crl("requireExplicitPolicy7subsubsubCARE2RE4Cert.crt",
                  "requireExplicitPolicy7subsubCARE2RE4CRL.crl");
   tester.add_untrusted_cert("InvalidrequireExplicitPolicyTest5EE.crt");
   tester.add_crl("InvalidrequireExplicitPolicyTest5EE.crt",
                  "requireExplicitPolicy7subsubsubCARE2RE4CRL.crl");

   WVFAIL(tester.validate());
}


WVTEST_MAIN("4.9.6 Valid Self-Issued requireExplicitPolicy Test6")
{
   Tester tester;
   tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
   tester.add_untrusted_cert("requireExplicitPolicy2CACert.crt");
   tester.add_crl("requireExplicitPolicy2CACert.crt",
                  "TrustAnchorRootCRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2SelfIssuedCACert.crt");
   tester.add_crl("requireExplicitPolicy2SelfIssuedCACert.crt",
                  "requireExplicitPolicy2CACRL.crl");
   tester.add_untrusted_cert("ValidSelfIssuedrequireExplicitPolicyTest6EE.crt");
   tester.add_crl("ValidSelfIssuedrequireExplicitPolicyTest6EE.crt",
                  "requireExplicitPolicy2CACRL.crl");

   WVPASS(tester.validate());
}


WVTEST_MAIN("4.9.7 Invalid Self-Issued requireExplicitPolicy Test7")
{
   Tester tester;
   tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
   tester.add_untrusted_cert("requireExplicitPolicy2CACert.crt");
   tester.add_crl("requireExplicitPolicy2CACert.crt",
                  "TrustAnchorRootCRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2SelfIssuedCACert.crt");
   tester.add_crl("requireExplicitPolicy2SelfIssuedCACert.crt",
                  "requireExplicitPolicy2CACRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2subCACert.crt");
   tester.add_crl("requireExplicitPolicy2subCACert.crt", 
                  "requireExplicitPolicy2CACRL.crl");
   tester.add_untrusted_cert("InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt");
   tester.add_crl("InvalidSelfIssuedrequireExplicitPolicyTest7EE.crt",
                  "requireExplicitPolicy2subCACRL.crl");

   WVFAIL(tester.validate());
}


WVTEST_MAIN("4.9.8 Invalid Self-Issued requireExplicitPolicy Test8")
{
   Tester tester;
   tester.add_trusted_cert("TrustAnchorRootCertificate.crt");
   tester.add_untrusted_cert("requireExplicitPolicy2CACert.crt");
   tester.add_crl("requireExplicitPolicy2CACert.crt",
                  "TrustAnchorRootCRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2SelfIssuedCACert.crt");
   tester.add_crl("requireExplicitPolicy2SelfIssuedCACert.crt",
                  "requireExplicitPolicy2CACRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2subCACert.crt");
   tester.add_crl("requireExplicitPolicy2subCACert.crt", 
                  "requireExplicitPolicy2CACRL.crl");
   tester.add_untrusted_cert("requireExplicitPolicy2SelfIssuedsubCACert.crt");
   tester.add_crl("requireExplicitPolicy2SelfIssuedsubCACert.crt",
                  "requireExplicitPolicy2subCACRL.crl");
   tester.add_untrusted_cert("InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt");   
   tester.add_crl("InvalidSelfIssuedrequireExplicitPolicyTest8EE.crt",
                  "requireExplicitPolicy2subCACRL.crl");

   WVFAIL(tester.validate());
}
