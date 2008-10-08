#ifndef __TESTMETHODS_H
#define __TESTMETHODS_H
#include <map>
#include <vector>
#include <wvfileutils.h>
#include <wvlogrcv.h>
#include <wvtest.h>
#include <wvx509.h>
#include <wvx509store.h>

#include "testdefuns.t.h"
#include "pathfinder.h"
#include "wvx509policytree.h" // for ANY_POLICY_OID


class Tester
{
public:
    Tester();

    ~Tester();

    void add_trusted_cert(WvStringParm certname);
    void add_untrusted_cert(WvStringParm certname);
    void add_intermediate_cert(WvStringParm certname);
    void add_crl(WvStringParm certname, WvStringParm crlname);

    bool validate();
    bool validate(WvStringParm initial_policy_oids, 
                  uint32_t flags = 0);
    bool _validate(WvStringParm initial_policy_set_tcl, uint32_t flags, 
                   WvX509Path &path);
    void path_found_cb(WvX509 *_cert, WvX509Path *_path, WvError err, void *);

    boost::shared_ptr<WvX509Store> trusted_store; 
    boost::shared_ptr<WvX509Store> intermediate_store; 
    WvX509Path path;

    // copy-pasted from wvx509path
    typedef std::multimap< std::string, boost::shared_ptr<WvCRL> > CRLMap;
    CRLMap crl_map;
    typedef std::pair< std::string, boost::shared_ptr<WvCRL> > CRLPair;

    bool validated;
    WvLog log;
};

#endif // __TESTMETHODS_H
