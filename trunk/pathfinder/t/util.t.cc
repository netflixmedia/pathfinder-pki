#include <wvfile.h>
#include <wvfileutils.h>
#include <wvtest.h>
#include <wvx509mgr.h>
#include <boost/shared_ptr.hpp>
#include "testmethods.t.h"
#include "util.h"


WVTEST_MAIN("guess encoding")
{
    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    WvString fname = wvtmpfilename("pathfinder-encoding-");
    
    WvDynBuf buf;
    ca.encode(WvX509::CertDER, buf);
    size_t old_used = buf.used();
    WVPASSEQ(guess_encoding(buf), WvX509::CertDER);
    WVPASSEQ(old_used, buf.used());

    {
        WvFile f(fname, O_CREAT|O_WRONLY);
        f.write(buf);
    }

    WVPASSEQ(guess_encoding(fname), WvX509::CertFileDER);

    ::unlink(fname);

    buf.zap();
    ca.encode(WvX509::CertPEM, buf);
    old_used = buf.used();
    WVPASSEQ(guess_encoding(buf), WvX509::CertPEM);
    WVPASSEQ(old_used, buf.used());

    {
        WvFile f(fname, O_CREAT|O_WRONLY);
        f.write(buf);       
    }

    WVPASSEQ(guess_encoding(fname), WvX509::CertFilePEM);

    ::unlink(fname);
}

WVTEST_MAIN("check MD5 or not")
{
    char md2cert[] = "-----BEGIN CERTIFICATE-----\n"
    "MIICNDCCAaECEAKtZn5ORf5eV288mBle3cAwDQYJKoZIhvcNAQECBQAwXzEL\n"
    "MAkGA1UEBhMCVVMxIDAeBgNVBAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMu\n"
    "MS4wLAYDVQQLEyVTZWN1cmUgU2VydmVyIENlcnRpZmljYXRpb24gQXV0aG9y\n"
    "aXR5MB4XDTk0MTEwOTAwMDAwMFoXDTEwMDEwNzIzNTk1OVowXzELMAkGA1UE\n"
    "BhMCVVMxIDAeBgNVBAoTF1JTQSBEYXRhIFNlY3VyaXR5LCBJbmMuMS4wLAYD\n"
    "VQQLEyVTZWN1cmUgU2VydmVyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MIGb\n"
    "MA0GCSqGSIb3DQEBAQUAA4GJADCBhQJ+AJLOesGugz5aqomDV6wlAXYMra6O\n"
    "LDfO6zV4ZFQD5YRAUcm/jwjiioII0haGN1XpsSECrXZogZoFokvJSyVmIlZs\n"
    "iAeP94FZbYQHZXATcXY+m3dM41CJVphIuR2nKRoTLkoRWZweFdVJVCxzOmmC\n"
    "sZc5nG1wZ0jl3S3WyB57AgMBAAEwDQYJKoZIhvcNAQECBQADfgBl3X7hsuyw\n"
    "4jrg7HFGmhkRuNPHoLQDQCYCPgmc4RKz0Vr2N6W3YQO2WxZpO8ZECAyIUwxr\n"
    "l0nHPjXcbLm7qt9cuzovk2C2qUtN8iD3zV9/ZHuO3ABc1/p3yjkWWW8O6tO1\n"
    "g39NTUJWdrTJXwT4OPjr0l91X817/OWOgHz8UA==\n"
    "-----END CERTIFICATE-----";
    
    char md5cert[] = "-----BEGIN CERTIFICATE-----\n"
    "MIICtzCCAiACAQAwDQYJKoZIhvcNAQEEBQAwgaMxCzAJBgNVBAYTAkVTMRIw\n"
    "EAYDVQQIEwlCQVJDRUxPTkExEjAQBgNVBAcTCUJBUkNFTE9OQTEZMBcGA1UE\n"
    "ChMQSVBTIFNlZ3VyaWRhZCBDQTEYMBYGA1UECxMPQ2VydGlmaWNhY2lvbmVz\n"
    "MRcwFQYDVQQDEw5JUFMgU0VSVklET1JFUzEeMBwGCSqGSIb3DQEJARYPaXBz\n"
    "QG1haWwuaXBzLmVzMB4XDTk4MDEwMTIzMjEwN1oXDTA5MTIyOTIzMjEwN1ow\n"
    "gaMxCzAJBgNVBAYTAkVTMRIwEAYDVQQIEwlCQVJDRUxPTkExEjAQBgNVBAcT\n"
    "CUJBUkNFTE9OQTEZMBcGA1UEChMQSVBTIFNlZ3VyaWRhZCBDQTEYMBYGA1UE\n"
    "CxMPQ2VydGlmaWNhY2lvbmVzMRcwFQYDVQQDEw5JUFMgU0VSVklET1JFUzEe\n"
    "MBwGCSqGSIb3DQEJARYPaXBzQG1haWwuaXBzLmVzMIGfMA0GCSqGSIb3DQEB\n"
    "AQUAA4GNADCBiQKBgQCsT1J0nznqjtwlxLyYXZhkJAk8IbPMGbWOlI6H0fg3\n"
    "PqHILVikgDVboXVsHUUMH2Fjal5vmwpMwci4YSM1gf/+rHhwLWjhOgeYlQJU\n"
    "3c0jt4BT18g3RXIGJBK6E2Ehim51KODFDzT9NthFf+G4Nu+z4cYgjui0OLzh\n"
    "PvYR3oydAQIDAQABMA0GCSqGSIb3DQEBBAUAA4GBACzzw3lYJN7GO9HgQmm4\n"
    "7mSzPWIBubOE3yN93ZjPEKn+ANgilgUTB1RXxafey9m4iEL2mdsUdx+2/iU9\n"
    "4aI+A6mB0i1sR/WWRowiq8jMDQ6XXotBtDvECgZAHd1G9AHduoIuPD14cJ58\n"
    "GNCr+Lh3B0Zx8coLY1xq+XKU1QFPoNtC\n"
    "-----END CERTIFICATE-----";
    
    char sha1cert[] = "-----BEGIN CERTIFICATE-----\n"
    "MIIEGjCCAwICEQDsoKeLbnVqAc/EfMwvlF7XMA0GCSqGSIb3DQEBBQUAMIHK\n"
    "MQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNV\n"
    "BAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5\n"
    "IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBD\n"
    "BgNVBAMTPFZlcmlTaWduIENsYXNzIDQgUHVibGljIFByaW1hcnkgQ2VydGlm\n"
    "aWNhdGlvbiBBdXRob3JpdHkgLSBHMzAeFw05OTEwMDEwMDAwMDBaFw0zNjA3\n"
    "MTYyMzU5NTlaMIHKMQswCQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24s\n"
    "IEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNV\n"
    "BAsTMShjKSAxOTk5IFZlcmlTaWduLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQg\n"
    "dXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWduIENsYXNzIDQgUHVibGljIFBy\n"
    "aW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBHMzCCASIwDQYJKoZI\n"
    "hvcNAQEBBQADggEPADCCAQoCggEBAK3LpRFpxlmr8Y+1GQ9Wzsy1HyDkniYl\n"
    "S+BzZYlZ3tCD5PUPtbut8XzoIfzk6AzufEUiGXaStBO3IFsJ+mGuqPKljYXC\n"
    "KtbeZjbSmwL0qJJgfJxptI8kHtCGUvYynEFYHiK9zUVilQhu0GbdU6LM8BDc\n"
    "VHOLBKFGMzNcF0C5nk3T875Vg+ixiY5afJqWIpA7iCXy0lOIAgwLePLmNxdL\n"
    "MEYH5IBtptiWLugs+BGzOA1mppvqySNb247i8xOOGlktqgLw7KSHZtzBP/XY\n"
    "ufTsgsbSPZUd5cBPhMnZo0QoBmrXRazwa2rvTl/4EYIeOGM0ZlDUPpNz+jDD\n"
    "Zq3/ky2X7wMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAj/ola09b5KROJ1Wr\n"
    "IhVZPMq1CtRK26vdoV9TxaBXOcLORyu+OshWv8LZJxA6sQU8wHcxuzrTBXtt\n"
    "mhwwjIDLk5Mqg6sFUYICABFna/OIYUdfA5PVWw3g8dShMjWFsjrbsIKr0csK\n"
    "vE+MW8VLADsfKoKmfjaF3H48ZwC15DtS4KjrXRX5xm3wrR0OhbepmnMUWluP\n"
    "QSjA1egtTaRezarZ7c7c2NU8Qh0XwRJdRTjDOPP8hS6DRkiy1yBfkjaP53kP\n"
    "mF6Z6PDQpLv1U70qzlmwr25/bLvSHgCwIe34QWKCudiyxLtGUPMxxY8BqHTr\n"
    "9Xgn2uf3ZkPznoM+IKrDNWCRzg==\n"
    "-----END CERTIFICATE-----";
    
    boost::shared_ptr<WvX509> cert;
    cert->decode(WvX509::CertPEM, md2cert);
    WVPASSEQ(is_md(cert), true);

    cert->decode(WvX509::CertPEM, md5cert);
    WVPASSEQ(is_md(cert), true);

    cert->decode(WvX509::CertPEM, sha1cert);
    
    WVPASSEQ(is_md(cert), true);
}
