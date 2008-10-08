/*
 * pathfinder.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include "pathfinder.h"

using namespace boost;
using namespace std;


PathFinder::PathFinder(shared_ptr<WvX509> &_cert, 
                       shared_ptr<WvX509Store> &_trusted_store, 
                       shared_ptr<WvX509Store> &_intermediate_store,
                       shared_ptr<WvCRLStore> &_crlstore,
                       uint32_t _validation_flags,
                       UniConf &_cfg,
                       PathFoundCb _cb) :
    cert_to_be_validated(_cert),
    trusted_store(_trusted_store),
    intermediate_store(_intermediate_store),
    crlstore(_crlstore),
    validation_flags(_validation_flags),
    path(new WvX509Path),
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


void PathFinder::find()
{
    check_cert(cert_to_be_validated);
}


void PathFinder::failed(WvStringParm reason)
{
    err.seterr(reason);
    failed();
}


void PathFinder::failed()
{
    path_found_cb(path, err);
}


void PathFinder::check_cert(shared_ptr<WvX509> &cert)
{
    if (!cert->isok())
    {
        failed("Certificate not valid");
        return;
    }

    if (!cert->get_ski())
    {
        failed("Certificate in path lacks an SKI");
        return;
    }

    log("Checked certificate. Seems to be ok.\n");

    // we allow at most one certificate of the same name that is not self
    // signed in the path
    if (cert->get_subject() != cert->get_issuer())
        added_certs[cert->get_subject().cstr()] = true;

    // check if we need to get more signers
    if (!!cert->get_aki() && cert->get_aki() != cert->get_ski())
    {
        log("Certificate (%s) we just got has an issuer (%s). We continue "
            "building the path.\n", cert->get_subject(), cert->get_issuer());
        path->prepend_cert(cert);
        get_signer(cert);
        return;
    }
    else if (!trusted_store->exists(cert.get()))
    {
        log("Trust anchor for cert not in store. Attempting to build "
            "bridge.\n");
        path->prepend_cert(cert);        
        if (!create_bridge(cert))
            return;
        // the process begins again
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

    if (!(validation_flags & WVX509_SKIP_CRL_CHECK))
    {
        log("Getting revocation information.\n");
        shared_ptr<WvX509> prev = *(path->begin());
        for (WvX509List::iterator i = path->begin(); i != path->end(); i++)
        {
            if (!get_revocation_info((*i), prev))
                return;
            
            prev = (*i);
        }
    }
    else
    {
        log("Not getting revocation information: checking disabled.\n");
        check_done(); // we check this in got_revocation_info in std. case
    }
}


bool PathFinder::get_signer(shared_ptr<WvX509> &cert) 
{
    log("Attempting to get signer.\n");

    WvX509List certlist;
    trusted_store->get(cert->get_aki(), certlist);
    intermediate_store->get(cert->get_aki(), certlist);
    if (!certlist.empty())
    {
        log("Certificate may be in trusted or intermediate store. Checking.\n");

        // prefer one that is self-signed if we have more than one...
        // also disallow certificate's whose issuer matches our subject
        // (we don't want to go around in circles!)
        if (certlist.size() > 1)
        {
            for (WvX509List::iterator i=certlist.begin();
                 i != certlist.end(); i++)
            {
                if ((*i)->get_issuer() == (*i)->get_subject() &&
                    (*i)->get_subject() == cert->get_issuer() && 
                    (*i)->get_issuer() != cert->get_subject() &&
                    added_certs.count((*i)->get_subject().cstr()) == 0)
                {
                    check_cert((*i));
                    return true;
                }
            }
        }

        // ... but if we don't have a self-signed cert, or we only
        // have one, then just take the first on the list. it's the best
        // we can do
        // again, disallow certificate's whose issuer matches our subject
        // (we don't want to go around in circles!)
        shared_ptr<WvX509> first = *certlist.begin();
        if (first->get_subject() == cert->get_issuer() && 
            first->get_issuer() != cert->get_subject() &&
            added_certs.count(first->get_subject().cstr()) == 0)
        {
            check_cert(first);
            return true;
        }

        log("Could not find certificate in intermediate store matching "
            "issuer name that may not have been previously added.\n");
    }

    WvStringList ca_urls;
    cert->get_ca_urls(ca_urls);

    DownloadFinishedCb cb = wv::bind(&PathFinder::signer_download_finished_cb, 
                                     this, _1, _2, _3, _4);

    return retrieve_object(ca_urls, cb);
}


void PathFinder::signer_download_finished_cb(WvStringParm urlstr, 
                                             WvStringParm mimetype, WvBuf &buf, 
                                             WvError _err)
{
    if (_err.geterr())
    {
        failed(WvString("Couldn't download certificate signer at url %s", 
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
	const unsigned char *p = buf.get(buf.used());
	pkcs7 = d2i_PKCS7(NULL, &p, len);
	
	// If this isn't a valid PKCS7 object... don't return anything
	if (!pkcs7)
	{
	    failed(WvString("%s is not a valid pkcs7 object!", urlstr)); 
	    return;
	}
	
	i = OBJ_obj2nid(pkcs7->type);
	if (i == NID_pkcs7_signed)
	    certs = pkcs7->d.sign->cert;
	else if (i == NID_pkcs7_signedAndEnveloped)
	    certs = pkcs7->d.signed_and_enveloped->cert;
	else
	{
	    failed("The PKCS7 bundle does not appear to have any certificates!");
	    return;
	}
	
	if (certs != NULL && sk_X509_num(certs) > 0)
	{
	    for (j = 0; j < sk_X509_num(certs); j++)
	    {
		shared_ptr<WvX509> x;
		X509 *_x = sk_X509_value(certs, j);
		x = shared_ptr<WvX509>(new WvX509(X509_dup(_x)));
		log("Extracting cert for %s from bundle.\n", x->get_subject().cstr());
		if (added_certs[x->get_subject().cstr()] == true)
		    log("Skipping '%s' because we've already got it in our list\n", x->get_subject());
		else
		    check_cert(x);
	    }
	}

        return;
    }

    shared_ptr<WvX509> cert(new WvX509);
    if (!strncmp("-----BEGIN", (const char *) buf.peek(0, 10), 10))
        cert->decode(WvX509::CertPEM, buf);
    else
        cert->decode(WvX509::CertDER, buf); 

    check_cert(cert);
}


bool PathFinder::create_bridge(shared_ptr<WvX509> &cert)
{
    WvX509List cross_certs;
    intermediate_store->get_cross_certs(cert, cross_certs);
    if (intermediate_store->count())
    {
      log("Creating bridge for certificate %s.\n", cert->get_subject());

      // first, attempt to find a cross cert which leads back to a trust anchor
      for (WvX509List::iterator i = cross_certs.begin(); 
           i != cross_certs.end(); i++)
      {
          log("Checking cross cert %s (with issuer %s)\n", (*i)->get_subject(),
              (*i)->get_issuer());

          if (trusted_store->exists((*i)->get_aki()) || 
              (!!cfg["intermediate CAs"].xget((*i)->get_aki()) && 1))
          {
              log("Found a cross certificate which leads back to a trust "
                "anchor. Choosing it.\n");
              check_cert((*i));
              return true;
          }
      }
    
      // otherwise, just follow the first one (if it exists) and hope for the
      // best. I don't think we need to support multiple paths to a bridge 
      // certificate at the moment. We have a check to make sure that 
      // we're not adding the same cross certificate twice.
      if (!cross_certs.empty() && 
          added_certs.count((*cross_certs.begin())->get_ski().cstr()) == 0)
      {
          check_cert((*cross_certs.begin()));
          return true;
      }
    
      failed("Couldn't find bridge which leads back to trust anchor");
      return false;
    }
    else
    {
      failed("No bridges defined");
      return false;
    }
}


bool PathFinder::get_revocation_info(shared_ptr<WvX509> &cert, 
                                     shared_ptr<WvX509> &signer)
{
    shared_ptr<RevocationFinder> rf(
        new RevocationFinder(cert, signer, path, crlstore, 
                             wv::bind(&PathFinder::got_revocation_info, this,
                                      _1, cert)));
    rfs.push_back(rf);
    return true;
}


void PathFinder::got_revocation_info(WvError &err, shared_ptr<WvX509> &cert)
{
    if (err.geterr())
    {
        failed(WvString("Failed to download revocation info for certificate %s", 
                        cert->get_subject()));
        return;
    }

    check_done();
}


bool PathFinder::retrieve_object(WvStringList &_urls, DownloadFinishedCb _cb)
{
    if (!_urls.count())
    {
        failed("No urls to download object needed to perform validation");
        return false;
    }

    log("%s urls to choose from.\n", _urls.count());

    while (_urls.count())
    {
        WvUrl url(_urls.popstr());
        if (url.getproto() == "http" || url.getproto() == "https")
        {
            shared_ptr<Downloader> d(new Downloader(url, pool, _cb));
            downloaders.push_back(d);
            return true;
        }
        else
            log("Protocol %s not supported for getting object.\n", url.getproto());
    }

    failed("Couldn't find valid URI to get object needed to perform validation");
    return false;
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
