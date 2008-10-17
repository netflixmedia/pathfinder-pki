#include <uniconfroot.h>
#include <wvfile.h>
#include <wvfileutils.h>
#include <wvtest.h>
#include <wvx509mgr.h>

#include "wvx509policytree.h" // for ANY_POLICY_OID
#include "pathvalidator.h"
#include "testdefuns.t.h"
#include "wvcrlcache.h"

using namespace boost;


static void validated_cb(shared_ptr<WvX509> &cert, bool valid, 
                         WvError err, int &validated_count, 
                         bool &validated_ok)
{
    wvcon->print("Validated cb for %s\n", cert->get_ski());
    validated_count++;
    validated_ok = valid;
}


WVTEST_MAIN("lookup in crlcache")
{
    const char *CRL_URI = "http://joeyjoejoejuniorshabadoo.invalid/mycrl.crl";
    WvString CRLSTORE_DIRNAME("/tmp/pathfinder-crlcache-%s", getpid());

    UniConfRoot cfg("temp:");
    shared_ptr<WvX509Store> trusted_store(new WvX509Store);
    shared_ptr<WvX509Store> intermediate_store(new WvX509Store);
    shared_ptr<WvCRLCache> crlcache(new WvCRLCache(CRLSTORE_DIRNAME));

    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    shared_ptr<WvX509> cacert(new WvX509(ca));
    trusted_store->add_cert(cacert);
    WvRSAKey rsakey(DEFAULT_KEYLEN);
    WvString certreq 
	= WvX509Mgr::certreq("cn=test.signed.com,dc=signed,dc=com", rsakey);
       
    shared_ptr<WvX509> cert(new WvX509);
    WvString certpem = ca.signreq(certreq);
    cert->decode(WvX509Mgr::CertPEM, certpem);
    WvStringList crl_urls;
    crl_urls.append(CRL_URI);
    cert->set_crl_urls(crl_urls);
    ca.signcert(*cert);

    // create the crl, add it to the crlcache
    mkdirp(CRLSTORE_DIRNAME);
    WvCRL crl(ca);
    WvString s = crl.encode(WvCRL::CRLPEM);
    WvConstStringBuffer buf(s);
    crlcache->add(CRL_URI, buf);

    int validated_count = 0;
    bool validated_ok = false;

    PathValidator p(cert, ANY_POLICY_OID, 0, trusted_store, 
                    intermediate_store, crlcache, cfg, 
                    wv::bind(&validated_cb, _1, _2, _3, 
                             wv::ref(validated_count),
                             wv::ref(validated_ok)));
    
    p.validate();

    // should all have validated ok, certificate not revoked.
    WVPASSEQ(validated_count, 1);
    WVPASSEQ(validated_ok, true);

    rm_rf(CRLSTORE_DIRNAME);
}


