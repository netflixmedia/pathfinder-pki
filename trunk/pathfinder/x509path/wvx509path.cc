/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007-2011, Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for 
 * details.
 */ 

#include <wvstrutils.h>
#include "wvx509path.h"
#include "wvx509policytree.h"

using namespace boost;
using namespace std;


WvX509Path::WvX509Path() :
    log("X509 Path", WvLog::Debug5)
{
}


WvX509Path::~WvX509Path()
{
}


WvString WvX509Path::get_end_entity_ski()
{
    if (x509_list.size() > 0)
        return x509_list.back()->get_ski();

    return WvString::null;
}


void WvX509Path::prepend_cert(shared_ptr<WvX509> &x509)
{
    log("Prepending cert %s to path.\n", x509->get_subject());
    x509_list.push_front(x509);
}


void WvX509Path::append_cert(shared_ptr<WvX509> &x509)
{
    log("Appending cert %s to path.\n", x509->get_subject());
    x509_list.push_back(x509);
}


void WvX509Path::add_crl(WvStringParm subject, shared_ptr<WvCRL> &crl)
{
    log("Adding a CRL for %s.\n", subject);
    crl_map.insert(CRLPair(subject.cstr(), crl));
}


void WvX509Path::add_ocsp_resp(WvStringParm subject,
                               shared_ptr<WvOCSPResp> &ocsp)
{
    log("Adding an OCSP response for %s.\n", subject);
    ocsp_map.insert(OCSPRespPair(subject.cstr(), ocsp));
}


void validate_crl(WvX509Store *store, shared_ptr<WvX509> &x509)
{
    WvX509Path crlpath;
}


void WvX509Path::validate_failed(WvStringParm errstring, WvError &err)
{
    log(WvLog::Error, "%s. Failed.\n", errstring);
    err.seterr(errstring);
}


bool WvX509Path::validate(shared_ptr<WvX509Store> &trusted_store, 
                          shared_ptr<WvX509Store> &intermediate_store,
                          WvStringList &initial_policy_set, 
                          uint32_t flags, 
                          WvX509List &extra_certs_to_be_validated,
                          WvError &err)
{
    if (x509_list.size() == 0)
        return true;

    bool check_revocation = !(flags & WVX509_SKIP_REVOCATION_CHECK);
    bool ignore_missing_crls = (flags & WVX509_IGNORE_MISSING_CRLS);
    bool check_policy = !(flags & WVX509_SKIP_POLICY_CHECK);
    bool initial_explicit_policy = (flags & WVX509_INITIAL_EXPLICIT_POLICY); 
    bool initial_inhibit_policy_mapping = 
    (flags & WVX509_INITIAL_POLICY_MAPPING_INHIBIT);

    int explicit_policy = 0;
    if (!initial_explicit_policy)
        explicit_policy = x509_list.size() + 1; 

    int policy_mapping = 0; 
    if (!initial_inhibit_policy_mapping)
        policy_mapping = x509_list.size() + 1;

    int inhibit_any_policy = x509_list.size() + 1;
    
    int max_path_length = x509_list.size();

    // first, find the trust anchor associated with the path. if we can't 
    // find one, we can't continue
    WvString trusted_aki = (*(x509_list.begin()))->get_aki();
    WvString trusted_issuer = (*(x509_list.begin()))->get_issuer();
    shared_ptr<WvX509> prev;
    if (!!trusted_aki) // look up with aki if we can, more reliable
        prev = trusted_store->get(trusted_aki);    
    else
        prev = trusted_store->get(trusted_issuer);

    if (!prev)
    {
        validate_failed(WvString("Trusted root for path (%s/%s) not in store", 
                                 trusted_aki, trusted_issuer), err);
        return false;
    }

    // initialize the policy tree (we won't use it if we're not checking 
    // policy)
    WvX509PolicyTree policy_tree;
    int policy_level = 0;

    shared_ptr<WvX509> cur;
    bool was_self_issued = false;
    WvX509List::iterator i = x509_list.begin();
    int count = 0;
    while (i != x509_list.end())
    {
        cur = (*i);
        log("Verifying certificate %s\n", cur->get_subject());
        // the requirements for a certificate to be self-issued are less 
        // stringent that the checks provided by WvX509::issuedbyca,
        // so we calculate this by hand.
        // FIXME: should we normalize the subject and issuer names for this 
        // check?
        was_self_issued = (cur->get_subject() == cur->get_issuer());

        if (!cur->validate())
        {
            validate_failed(WvString("Certificate '%s' not valid", 
                                     cur->get_subject()), err);
            return false;
        }

        if (!cur->issuedbyca(*(prev.get())))
        {
            validate_failed(WvString("Certificate's issuer (%s) does not "
                                     "match working issuer name (%s)", cur->get_issuer(),
                                     prev->get_subject()), err);
            return false;
        }
        
        if (!cur->signedbyca(*(prev.get())))
        {
            validate_failed(WvString("Certificate '%s' not signed by working "
                                     "certificate (%s)", cur->get_subject(),
                                     prev->get_subject()), err);
            return false;
        }

        // OCSP validation is pretty simple: look it up in the map, make 
        // sure our current certificate is not revoked, then add the OCSP
        // responder certificate to our list of extra certificates to be 
        // validated. note that we also need aki info to make it work.
        bool validated_ocsp = false;        
        bool have_aki = !!cur->get_aki();
        bool have_ski = !!cur->get_ski();
        if (check_revocation) 
        {
            pair<OCSPRespMap::iterator, OCSPRespMap::iterator> iterpair = 
            ocsp_map.equal_range(cur->get_subject().cstr());
            log(WvLog::Info, "Looking up %s in OCSP map.\n",
                             cur->get_subject());
            if (iterpair.first != iterpair.second)
            {
                shared_ptr<WvOCSPResp> resp = (*iterpair.first).second;
                WvX509 resp_signer = resp->get_signing_cert();
                
                WvOCSPResp::Status status = resp->get_status(*cur, *prev);
                if (status != WvOCSPResp::Good)
                {
                    validate_failed(WvString("Certificate %s's OCSP response "
                                             "does not check out (status: %s)",
                                             cur->get_subject(), 
                                             WvOCSPResp::status_str(status)),
                                    err);
                    return false;
                }
                
                if (!resp_signer)
                {
                    validate_failed(WvString("Certificate %s's OCSP response "
                                             "does not have a signing "
                                             "certificate", 
                                             cur->get_subject()), err);
                    return false;
                }

                if (!resp->signedbycert(resp_signer))
                {
                    validate_failed(WvString("Certificate %s's OCSP response "
                                             "is not properly signed by OCSP "
                                             "response signer",
                                             cur->get_subject()), err);
                    return false;
                }

                bool responder_has_ocsp_signing_key_usage = false;
                WvStringList ext_key_usage;
                ext_key_usage.split(resp_signer.get_ext_key_usage(), ";\n");
                WvStringList::Iter i(ext_key_usage);
                for (i.rewind(); i.next();)
                {
                    if (i() == "OCSP Signing")
                    {
                        responder_has_ocsp_signing_key_usage = true;
                        break;
                    }
                }
                if (!responder_has_ocsp_signing_key_usage)
                {
                    validate_failed(WvString("Certificate %s's OCSP responder "
                                             "does not have OCSP Signing in "
                                             "its extended key usage",
                                             cur->get_subject()), err);
                    return false;
                }
                
                if ((have_ski && resp_signer.get_aki() == cur->get_ski())
                        ||
                   (resp_signer.get_issuer() == cur->get_subject()))
                {
                    // this is somewhat questionable, but allow it for now:
                    // some certificates in the wild are the signer of their
                    // own OCSP responder
                    log(WvLog::Warning, "Certificate %s's OCSP responder's "
                        "seems to be signed by the current certificate. This "
                        "is somewhat questionable.\n");
                }
                else if ((have_aki && resp_signer.get_aki() != cur->get_aki())
                        ||
                    (resp_signer.get_issuer() != cur->get_issuer()))
                {
                    if (have_aki)
                        validate_failed(WvString("Certificate %s's OCSP "
                                             "responder's AKI (%s) does not "
                                             "match own (%s)",
                                             cur->get_subject(), 
                                             resp_signer.get_aki(),
                                             cur->get_aki()), err);
                    else
                        validate_failed(WvString("Certificate %s's OCSP "
                                             "responder's issuer (%s) does "
                                             "not match own (%s)",
                                             cur->get_subject(),
                                             resp_signer.get_issuer(),
                                             cur->get_issuer()), err);
                    return false;
                }

                // validate the cert *UNLESS* the id-pkix-ocsp-nocheck
                // extension is present. (sigh)
                if (X509_get_ext_by_NID(resp_signer.get_cert(),
                                        NID_id_pkix_OCSP_noCheck, -1) < 0)
                {
                    extra_certs_to_be_validated.push_back(
                        shared_ptr<WvX509>(new WvX509(resp_signer)));
                }
                else
                {
                    log(WvLog::Info, "Not validating the OCSP signing "
                        "certificate (%s) since it asserts the "
                        "id-pkix-ocsp-nocheck extension.\n",
                        resp_signer.get_subject());
                }
                validated_ocsp = true;
            }
        }
            
        // CRL validation is much more involved... we try to follow what's 
        // laid out in rfc3280 to the letter
        if (check_revocation && !validated_ocsp)
        {
            pair<CRLMap::iterator, CRLMap::iterator> iterpair = 
                crl_map.equal_range(cur->get_subject().cstr());

            bool one_valid_crl = false;
            for (CRLMap::iterator j = iterpair.first; j != iterpair.second; j++)
            {
                shared_ptr<WvCRL> crl = (*j).second;

                // we need to trim spaces and convert to lower case: 
                // differences in spacing or case shouldn't make a difference 
                // for validation
                WvString crl_issuer = strreplace(crl->get_issuer(), " ", "");
                strlwr(crl_issuer.edit());
                WvString cert_issuer = strreplace(cur->get_issuer(), " ", "");
                strlwr(cert_issuer.edit());
                WvString crl_aki = crl->get_aki();
                bool crl_signer_untrusted = false;

                shared_ptr<WvX509> crl_signer;
                if (prev->get_ski() == crl_aki)
                    crl_signer = prev;
                if (!crl_signer && prev->get_subject() == crl_issuer)
                    crl_signer = prev;
                if (!crl_signer)                
                    crl_signer = trusted_store->get(crl_aki);                
                // as a last resort, search in the intermediate store for a 
                // crl signer. this crl signer will need to be validated
                // seperately
                if (!crl_signer)
                {
                    crl_signer = intermediate_store->get(crl_aki);
                    crl_signer_untrusted = true;
                }

                if (!crl_signer)
                {
                    log(WvLog::Info, "CRL signer is not the certificate's "
                        "signer, nor can we find it in the trusted store.\n", 
                        cur->get_subject());
                    continue;
                }

                if (crl->validate(*(crl_signer.get())) != WvCRL::VALID)
                {
                    log(WvLog::Info, "Certificate revocation list for %s is "
                        "not valid.\n", cur->get_subject());
                    continue;
                }

                // we don't support indirect crls yet, so in addition to 
                // the CRL needing to be validated by its issuer, the 
                // issuer's name of the crl should match the issuer name 
                // of the certificate we are processing.
                
                if (crl_issuer != cert_issuer)
                {
                    log(WvLog::Info, "CRL's issuer (%s) does not match "
                        "certificate's issuer (%s).\n", crl_issuer, 
                        cert_issuer);
                    continue;
                }

                // if we got this far, our CRL is valid. however, we may need
                // to validate our CRL signer if it's untrusted
                one_valid_crl = true;
                if (crl_signer_untrusted)
                    extra_certs_to_be_validated.push_back(crl_signer);

                if (crl->isrevoked(*(cur.get())))
                {
                    log(WvLog::Error, "Certificate %s is revoked according to "
                        "CRL.\n", cur->get_subject());
                    return false;
                }
            }
        
            if (!one_valid_crl)
            {
                WvStringList crl_urls;
                cur->get_crl_urls(crl_urls);
                if (ignore_missing_crls && !crl_urls.count())
                {
                    log("No crl specified for certificate %s, but ignoring "
                        "missing CRLs.\n", cur->get_subject());
                }
                else
                {
                    validate_failed(WvString("No valid crl for certificate "
                                             "%s", cur->get_subject()), err);
                    return false;
                }
            }
        }

        if (check_policy)
        {
            ++policy_level;
            WvStringList policies;
            cur->get_policies(policies);
            // FIXME: we should really be checking whether the policies 
            // extension is present, not how many policies we got out of
            // a possible existent policies extension
            if (policies.count()) 
            {
                bool linked_policy = false;
                bool contains_any_policy = false;
                WvStringList::Iter j(policies);
                for (j.rewind(); j.next();)
                {
                    if (j() != ANY_POLICY_OID)
                        linked_policy |= policy_tree.link(j(), (policy_level-1), false);
                    else
                        contains_any_policy = true;
                }
                // if we didn't succeed, try to extend via a last node with the 
                // expected policy "any policy" 
                if (!linked_policy)
                {
                    for (j.rewind(); j.next();)
                    {
                        policy_tree.link(j(), (policy_level-1), true);
                    }
                }

                // if the certificate to be processed has a policy of anyPolicy
                // and certain conditions are met, we further extend the tree
                if (contains_any_policy && (inhibit_any_policy > 0 || 
                                            (count < (x509_list.size() - 1) &&
                                             was_self_issued)))
                {
                    policy_tree.extend_any_policy(policy_level-1);
                }

                // prune the policy tree (remove any nodes below the current policy
                // level without any children)
                policy_tree.prune(policy_level);
            }
            else // no policies extension: set policy tree to null (by pruning)
                policy_tree.prune(policy_level);
        }
        
        // prepare for next certificate (i+1)
        if ((++i) != x509_list.end())
        {
            WvX509::PolicyMapList list;
            if (cur->get_policy_mapping(list))
            { 
                // verify that anyPolicy does not exist in policy mapping
                WvX509::PolicyMapList::Iter j(list);
                for (j.rewind(); j.next();)
                {
                    if (j().issuer_domain == ANY_POLICY_OID || 
                        j().subject_domain == ANY_POLICY_OID)
                    {
                        validate_failed(WvString("Issuer domain (%s) or "
                                                 "subject domain (%s) is "
                                                 "anyPolicy", 
                                                 j().issuer_domain, 
                                                 j().subject_domain), err);
                        return false;
                    }
                }
                // if not, and we're not inhibiting policy mapping
                // append the mapping to our policy tree
                if (policy_mapping > 0)
                    policy_tree.append_mapping(list, policy_level);
                else
                {
                    log("Policy mapping is 0. Removing all policies with "
                        "issuer domain in policy mapping.\n");
                    for (j.rewind(); j.next();)
                        policy_tree.remove(j().issuer_domain, policy_level);
                    policy_tree.prune(policy_level);
                }
            }

            if (!was_self_issued)
            {
                log("Decrementing explicit policy and policy mapping.\n");
                if (explicit_policy > 0)
                    explicit_policy--;
                if (policy_mapping > 0)
                    policy_mapping--;
            }

            int require_explicit_policy;
            int inhibit_policy_mapping;
            if (cur->get_policy_constraints(require_explicit_policy, 
                                            inhibit_policy_mapping))
            {
                if (require_explicit_policy >= 0 && require_explicit_policy < explicit_policy)
                {
                    log("Policy constraints found. Setting explicit policy to %s\n",
                        require_explicit_policy);
                    explicit_policy = require_explicit_policy;
                }
                if (inhibit_policy_mapping >= 0 && inhibit_policy_mapping < policy_mapping)
                {
                    log("Policy constraints found. Setting policy mapping to %s\n",
                        inhibit_policy_mapping);
                    policy_mapping = inhibit_policy_mapping;
                }
            }
            
            // step (k)
            bool is_ca;
            int pathlen_constraint;
            if (cur->get_basic_constraints(is_ca, pathlen_constraint))
            {
                if (!is_ca)
                {
                    validate_failed("Certificate is not a CA according to "
                                    "basicConstraints extension", err);
                    return false;
                }
            }
            else
                return false;

            // step (l)
            if (!was_self_issued)
            {
                if (max_path_length > 0)
                    max_path_length--;
                else
                {
                    validate_failed("Maximum path length exceeded", err);
                    return false;
                }
            }

            // step (m)
            if (pathlen_constraint >= 0 && 
                pathlen_constraint < max_path_length)
            {
                log("Path length constraint set and is less than "
                    "max_path_length. Setting max_path_length to %s.\n",
                    max_path_length);
                max_path_length = pathlen_constraint;
            }

            count++;
        }

        prev = cur;
    }

    // wrap up procedure
    if (check_policy)
    {
        if (!was_self_issued && explicit_policy > 0)
            explicit_policy--;

        if (explicit_policy > 0)
        {
            log("Explicit policy is greater than 0 (%s), not checking policy "
                "tree.\n", explicit_policy);
            return true;
        }
        log("Explicit policy is 0. Checking policy tree.\n");

        if (policy_tree.isnull())
        {
            validate_failed("Policy tree is null at beginning of policy "
                            "checking", err);
            return false;
        }

        // check for any policy in initial policy, if it's not there,
        // we need to check the intersection. if it is, we simply 
        // return true.
        bool any_policy_in_initial_policy = false;
        WvStringList::Iter i(initial_policy_set);
        for (i.rewind(); i.next();)
        {
            if (i() == ANY_POLICY_OID)
            {
                any_policy_in_initial_policy = true;
                break;
            }
        }

        if (any_policy_in_initial_policy)
            return true;

        policy_tree.intersection(initial_policy_set, policy_level);
        if (policy_tree.isnull())
        {
            validate_failed("Policy tree is null during policy "
                            "checking", err);
            return false;
        }
    }

    return true;
}


