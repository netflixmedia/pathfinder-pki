#include "testmethods.t.h"
#include "wvx509policytree.h"
#include <openssl/err.h>

using namespace boost;


Tester::Tester() :
    trusted_store(new WvX509Store),
    intermediate_store(new WvX509Store),
    log("Pathfinder Test Harness", WvLog::Debug5)
{
    validated = false;
    ERR_load_ERR_strings();
}


Tester::~Tester()
{
}


void Tester::add_trusted_cert(WvStringParm certname)
{
    shared_ptr<WvX509> x(new WvX509);
    x->decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, certname));
    trusted_store->add_file(WvString("%s%s", CERTS_PATH, certname));
}


void Tester::add_untrusted_cert(WvStringParm certname)
{
    shared_ptr<WvX509> x(new WvX509);
    x->decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, certname));
    intermediate_store->add_cert(x);
    path.append_cert(x);
}


void Tester::add_intermediate_cert(WvStringParm certname)
{
   shared_ptr<WvX509> x(new WvX509);
   x->decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, certname));
   intermediate_store->add_cert(x);
}


void Tester::add_crl(WvStringParm certname, WvStringParm crlname)
{
    WvX509 x;
    x.decode(WvX509::CertFileDER, WvString("%s%s", CERTS_PATH, certname));
    shared_ptr<WvCRL> crl(new WvCRL);
    crl->decode(WvCRL::CRLFileDER, WvString("%s%s", CRLS_PATH, crlname));
    path.add_crl(x.get_ski(), crl);
    crl_map.insert(CRLPair(x.get_ski().cstr(), crl));
}


bool Tester::validate()
{
    return validate(wvtcl_escape(ANY_POLICY_OID), 0);
}


bool Tester::validate(WvStringParm initial_policy_set_tcl, 
                      uint32_t flags)
{
    return _validate(initial_policy_set_tcl, flags, path);
}


bool Tester::_validate(WvStringParm initial_policy_set_tcl, uint32_t flags, 
                       WvX509Path &path)
{
    WvStringList initial_policy_set;
    wvtcl_decode(initial_policy_set, initial_policy_set_tcl);

    WvX509Path::WvX509List extra_certs;

    WvError err;
    validated = path.validate(trusted_store, intermediate_store, 
                              initial_policy_set, flags, extra_certs, err);
    log("Initial path validated, certificate is %svalid (reason: %s).\n", 
        validated ? "" : "NOT ", err.errstr());
    for (WvX509Path::WvX509List::iterator i = extra_certs.begin(); 
         i != extra_certs.end(); i++)
    {
        log("Validating extra path %s\n", (*i)->get_subject());
        WvX509Path extra_path;
        
        for (CRLMap::iterator j = crl_map.begin(); j != crl_map.end(); j++)
        {
            extra_path.add_crl((*j).first.c_str(), (*j).second);
        }
        
        extra_path.prepend_cert((*i));
        shared_ptr<WvX509> cur((*i));
        while (!trusted_store->exists(cur->get_aki()))
        {
            shared_ptr<WvX509> next = intermediate_store->get(cur->get_aki());
            if (!next)
            {
                log("Couldn't find cert with aki %s to build extra path!\n");
                return false;
            }

            extra_path.prepend_cert(next);
            cur = next;
        }

        validated &= _validate(wvtcl_escape(ANY_POLICY_OID), 0, extra_path);
        if (!validated)
            return false;
    }

    return validated;
}
