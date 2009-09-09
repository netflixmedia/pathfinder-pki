/*
 * pathfinder.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */
#include <wvstrutils.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include "pathfinder.h"
#include "util.h"

using namespace boost;
using namespace std;

PathFinder::PathFinder(shared_ptr<WvX509> &_cert, 
                       shared_ptr<WvX509Store> &_trusted_store, 
                       shared_ptr<WvX509Store> &_intermediate_store,
                       shared_ptr<WvCRLCache> &_crlcache,
                       uint32_t _validation_flags,
                       bool _check_ocsp,
                       UniConf &_cfg,
                       PathFoundCb _cb) :
    cert_to_be_validated(_cert),
    trusted_store(_trusted_store),
    intermediate_store(_intermediate_store),
    crlcache(_crlcache),
    validation_flags(_validation_flags),
    path(new WvX509Path),
    check_ocsp(_check_ocsp),
    check_bridges(false),
    cfg(_cfg),
    got_cert_path(false),
    path_found_cb(_cb),
    log("PathFinder")
{
    pool = new WvHttpPool();
    WvIStreamList::globallist.append(pool, false, "pathfinder http pool");
}


PathFinder::~PathFinder()
{
    WvIStreamList::globallist.unlink(pool);
    WVRELEASE(pool);
}


void PathFinder::wouldfail(WvStringParm str)
{
    log("%s\n", str);
    //err.seterr(str);
}


void PathFinder::find()
{
    check_bridges = false;  // go for direct trust first...
    check_cert(cert_to_be_validated);
    if (!got_cert_path)
    {
        if (intermediate_store->count() == 0)
        {
            log("Trust anchor for cert not found in store, and no bridges "
                "defined.  Giving up.\n");
            if (!err.geterr())
                err.seterr("Couldn't build path.  "
                           "Check the logs to find out why.");
            path_found_cb(path, err);
            return;
        }

        log("Trust anchor for cert not in store. Starting over, but looking "
            "for bridges this time.\n");
        while (path->pathsize() > 0)
        {
            log("Popping off %s\n", path->subject_at_front());
            added_certs.erase(path->subject_at_front().cstr());
            path->pop_front();
        }
        check_bridges = true;   // go for bridged trust this time...
        check_cert(cert_to_be_validated);

        if (!got_cert_path)
        {
            log("Trust anchor for cert not in store, and couldn't build "
                "a bridge either.  Giving up.\n");
            if (!err.geterr())
                err.seterr("Couldn't build path.  "
                           "Check the logs to find out why.");
            path_found_cb(path, err);
        }
    }
}


void PathFinder::check_cert(shared_ptr<WvX509> &cert)
{
    if (!cert->isok())
    {
        wouldfail(WvString("Certificate not valid (%s).", cert->get_subject()));
        return;
    }

    log("Checked certificate (%s). Seems to be ok.\n", cert->get_subject());

    log("Is this certificate signed with MD5 or MD2? ");
    bool md = is_md(cert);
    log(md ? "Yes\n" : "No\n");
    
    if (md && cfg["Defaults/Allow MD5"].xgetint(0) == 0)
    {
        wouldfail("Certificate signed using a disallowed Hash algorithm.");
        return;
    }
    
    // we allow at most one certificate of the same name that is not self
    // signed in the path
    if (cert->get_subject() != cert->get_issuer())
        added_certs[cert->get_subject().cstr()] = true;

    // check if we need to get more signers
    if ((!!cert->get_aki() && cert->get_aki() != cert->get_ski()) || 
        cert->get_subject() != cert->get_issuer())
    {
        log("Certificate (%s) we just got has an issuer (%s). We continue "
            "building the path.\n", cert->get_subject(), cert->get_issuer());
        path->prepend_cert(cert);
        get_signer(cert);
        return;
    }
    else if (!trusted_store->exists(cert.get()))
    {
        log("Got a self-signed root that I don't trust.\n");
        return;
    }
    else
    {
        log("Certificate has no non-self signers (and should be a trust "
            "anchor). Stop, perform path validation.\n");
        got_cert_path = true;
    }

    // otherwise, we've hit a self-signed certificate and are done fetching
    // files to build the path remotely... 

    log("Done building path.\n");

    if (!(validation_flags & WVX509_SKIP_REVOCATION_CHECK))
    {
        log("Getting revocation information for path of length %s.\n",
                path->pathsize());
        shared_ptr<WvX509> prev = cert;
        
        for (WvX509List::iterator i = path->begin(); i != path->end(); i++)
        {
            get_revocation_info((*i), prev);    // populates rfs
            prev = (*i);
        }
        for (RevocationFinderList::iterator i = rfs.begin();
             i != rfs.end(); i++)
        {
            (*i)->find();
        }
    }
    else
    {
        log("Not getting revocation information: checking disabled.\n");
        check_done(); // we check this in got_revocation_info in std. case
    }
}


WvString PathFinder::storename() const
{
    if (check_bridges)
        return "trusted or intermediate store";
    else
        return "trusted store";
}


void PathFinder::get_signer(shared_ptr<WvX509> &cert) 
{
    log("Attempting to get signer.\n");

    // first, check if we don't have the certificate explicitly defined
    // somewhere (FIXME: tons of duplication between this and similar code
    // in revocationfinder)

    WvString hardcoded_loc = cfg["CA Location"].xget(
        url_encode(cert->get_issuer(), "/="));
    if (!!hardcoded_loc)
    {
        shared_ptr<WvX509> cacert(new WvX509);
        cacert->decode(guess_encoding(hardcoded_loc), hardcoded_loc);
        
        if (!cacert->isok())
        {
            wouldfail(WvString("Explicitly defined CA for certificate %s (in "
                        "file %s, but certificate not ok", 
                        cert->get_subject(), hardcoded_loc));
            return;
        }

        check_cert(cacert);
        return;
    }

    // next, check to see if the certificate is in the trusted store, and
    // (if we're checking for bridges) the intermediate store.
    WvX509List certlist;
    trusted_store->get(cert->get_aki(), certlist);
    if (check_bridges)
        intermediate_store->get(cert->get_aki(), certlist);
    if (!certlist.empty())
    {
        log("Evaluating %s: Issuer's Certificate (%s) may be in %s "
            "%s times. Checking.\n",
            cert->get_ski(), cert->get_aki(), storename(), certlist.size());

        // prefer one that is self-signed if we have more than one...
        // also disallow certificates whose issuer matches our subject
        // (we don't want to go around in circles!)
        if (certlist.size() > 1)
        {
            for (WvX509List::iterator i=certlist.begin();
                 i != certlist.end(); i++)
            {
                //log("Taking a look at %s issued by %s\n",
                //    (*i)->get_subject(), (*i)->get_issuer());
                if ((*i)->get_issuer() == (*i)->get_subject() &&
                    (*i)->get_subject() == cert->get_issuer() && 
                    (*i)->get_issuer() != cert->get_subject() &&
                    added_certs.count((*i)->get_subject().cstr()) == 0)
                {
                    //log("Found a self-signed cert!  subj=%s, issuer=%s, "
                    //    "ski=%s, aki=%s\n",
                    //    (*i)->get_subject(), (*i)->get_issuer(),
                    //    (*i)->get_ski(), (*i)->get_aki());
                    check_cert((*i));
                    return;
                }
            }
        }

        // ... but if we don't have a self-signed cert, or we only
        // have one, then loop through anything that matches.  If it turns
        // out we've taken a wrong branch, pop back down to a saved state
        // and take the next branch.
        // again, disallow certificates whose issuer matches our subject
        // (we don't want to go around in circles!)
        // for efficiency, sort the list so that entries corresponding to
        // an [Intermediate CAs] entry are first.
        for (WvX509List::iterator i=certlist.begin();
             i != certlist.end(); i++)
        {
            if (!!cfg["Intermediate CAs"].xget((*i)->get_aki()))
            {
                log("Moving %s to the front of the list.\n",
                    (*i)->get_issuer());
                certlist.push_front(*i);
                i = certlist.erase(i);
                i--;
            }
        }
        for (WvX509List::iterator i=certlist.begin();
             i != certlist.end(); i++)
        {
            //log("Taking a look (2) at %s issued by %s\n",
            //    (*i)->get_subject(), (*i)->get_issuer());
            examine_signer((*i), cert);
            if (got_cert_path)
                return; // done!
        }

        log("Could not find certificate in %s "
            "matching issuer name that may not have been previously added.\n",
            storename());
    }

    WvStringList ca_urls;
    cert->get_ca_urls(ca_urls);

    DownloadFinishedCb cb = wv::bind(&PathFinder::signer_download_finished_cb, 
                                     this, cert, _1, _2, _3, _4);

    retrieve_object(ca_urls, cb);
}


// examines a potential certificate 'i' to see if it is a valid issuer of
// 'cert'.  If it is, and we haven't used it before, then try building a
// path through it.  If that fails, pop back down to the same place and
// return.
void PathFinder::examine_signer(shared_ptr<WvX509> &i, shared_ptr<WvX509> &cert)
{
    if (i->get_subject() == cert->get_issuer() &&
        i->get_issuer() != cert->get_subject() &&
        added_certs.count(i->get_subject().cstr()) == 0)
    {
        //log("Found a cert!  subj=%s, issuer=%s, ski=%s, aki=%s\n",
        //    i->get_subject(), i->get_issuer(), i->get_ski(), i->get_aki());
        WvString curfront = path->subject_at_front();
        check_cert(i);
        if (!got_cert_path)
        {
            log("Path discovery hit a dead end.\n");
            while (path->subject_at_front() != curfront)
            {
                log("Popping off %s\n", path->subject_at_front());
                added_certs.erase(path->subject_at_front().cstr());
                path->pop_front();
            }
        }
    }
}


void PathFinder::signer_download_finished_cb(shared_ptr<WvX509> &cert, 
                                             WvStringParm urlstr, 
                                             WvStringParm mimetype, WvBuf &buf, 
                                             WvError _err)
{
    if (_err.geterr())
    {
        wouldfail(WvString("Couldn't download certificate signer at url %s", 
                        urlstr));
        return;
    }

    log("Got certificate with mimetype %s.\n", mimetype);

    // eugh, big hack to handle certificates bundled inside a pkcs7
    if (strstr(urlstr, ".p7c") || strstr(urlstr, ".p7b"))
    {
        log("Certificate from url %s is encoded in pkcs7. Decoding.\n", 
            urlstr);
	PKCS7 *pkcs7;
	STACK_OF(X509) *certs = NULL;
	int i,j;
	int len = buf.used();

        if (guess_encoding(buf) == WvX509::CertPEM)
        {
            log("PKCS7 file appears to be in PEM format, but is probably "
                "not supposed to be.  Decoding anyway.\n");
            BIO *membuf = BIO_new(BIO_s_mem());
            BIO_write(membuf, buf.get(buf.used()), buf.used());
            pkcs7 = PEM_read_bio_PKCS7(membuf, NULL, NULL, NULL);
            BIO_free_all(membuf);
        }
        else
        {
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
            const unsigned char *p = buf.get(buf.used());
#else
            const unsigned char *q = buf.get(buf.used());
            unsigned char *p = const_cast<unsigned char *>(q);
#endif
            pkcs7 = d2i_PKCS7(NULL, &p, len);
        }
	
	// If this isn't a valid PKCS7 object... don't return anything
	if (!pkcs7)
	{
	    wouldfail(WvString("%s is not a valid pkcs7 object!", urlstr)); 
	    return;
	}
	
	i = OBJ_obj2nid(pkcs7->type);
	if (i == NID_pkcs7_signed)
	    certs = pkcs7->d.sign->cert;
	else if (i == NID_pkcs7_signedAndEnveloped)
	    certs = pkcs7->d.signed_and_enveloped->cert;
	else
	{
	    wouldfail("The PKCS7 bundle does not appear to have any certificates!");
	    return;
	}
	
	if (certs != NULL && sk_X509_num(certs) > 0)
	{
	    for (j = 0; j < sk_X509_num(certs); j++)
	    {
		shared_ptr<WvX509> x;
		X509 *_x = sk_X509_value(certs, j);
		x = shared_ptr<WvX509>(new WvX509(X509_dup(_x)));
                //log("Taking a look (3) at %s issued by %s\n",
                //    x->get_subject(), x->get_issuer());
		log("Extracting cert for %s from bundle.\n",
                    x->get_subject().cstr());
                examine_signer(x, cert);
                if (got_cert_path)
                    return; // done!
	    }
	}

        return;
    }

    shared_ptr<WvX509> cert2(new WvX509);
    if (guess_encoding(buf) == WvX509::CertPEM)
        cert2->decode(WvX509::CertPEM, buf);
    else
        cert2->decode(WvX509::CertDER, buf); 

    check_cert(cert2);
}


void PathFinder::get_revocation_info(shared_ptr<WvX509> &cert, 
                                     shared_ptr<WvX509> &signer)
{
    shared_ptr<RevocationFinder> rf(
        new RevocationFinder(cert, signer, path, crlcache, check_ocsp, cfg,
                             wv::bind(&PathFinder::got_revocation_info, this,
                                      _1, cert)));
    rfs.push_back(rf);
    return;
}


void PathFinder::got_revocation_info(WvError &err, shared_ptr<WvX509> &cert)
{
    if (err.geterr())
    {
        wouldfail(WvString("Failed to download revocation info for certificate %s", 
                        cert->get_subject()));
    }

    check_done();
}


void PathFinder::retrieve_object(WvStringList &_urls, DownloadFinishedCb _cb)
{
    if (!_urls.count())
    {
        wouldfail("No urls to download object needed to perform validation");
        return;
    }

    while (_urls.count())
    {
        WvUrl url(_urls.popstr());
        if (url.isok() && (url.getproto() == "http"  || 
                           url.getproto() == "https")) /*||
            url.getproto() == "ldap"  ||
            url.getproto() == "ldaps")*/    // LDAP downloads don't
            // actually work properly yet.  WvURL doesn't understand these
            // particular protocol identifiers.  Removing these for now...
            // ANOTHER problem we'll have is what to do when the HTTP
            // download succeeds, but we hit a root we don't trust?  Do we
            // then rewind and try the LDAP?  I'm not sure that'll work as
            // written.  When re-enabling the ldap download code,
            // definitely keep that in mind...
        {
            shared_ptr<Downloader> d(new Downloader(url, pool, _cb));
            downloaders.push_back(d);

            // do NOT return until our downloader is done and the callback
            // has been run, or else a get_signer() somewhere farther up
            // the stack can proceed to validate other paths before we know
            // if this one is any good!
            while (!d->is_done() && WvIStreamList::globallist.isok())
                WvIStreamList::globallist.runonce();

            if (!got_cert_path)
                wouldfail("Downloaded signer did not lead to a valid "
                          "trust path.");
            //if (got_cert_path)
                // we don't deal well with going on to try the next URL...
                return;
        }
        else if (!!url.getproto())
            log("Protocol %s not supported for getting object.\n", url.getproto());
    }

    wouldfail("Couldn't find valid URI to get object needed to perform "
              "validation.");
    return;
}


void PathFinder::check_done()
{
    if (!got_cert_path)
        return;

    for (DownloaderList::iterator i = downloaders.begin();
         i != downloaders.end(); i++)
    {
        if (!(*i)->is_done())
            return;
    }

    for (RevocationFinderList::iterator i = rfs.begin(); i != rfs.end(); i++)
    {
        if (!(*i)->is_done())
            return;
    }

    log("All objects needed to validate path have been put into place. We "
        "are done\n");
    path_found_cb(path, err);
}
