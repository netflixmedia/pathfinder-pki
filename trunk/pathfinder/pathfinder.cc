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
                       UniConf &_cfg,
                       PathFoundCb _cb, 
                       void *_userdata) :
    cert_to_be_validated(_cert),
    trusted_store(_trusted_store),
    intermediate_store(_intermediate_store),
    path(new WvX509Path),
    userdata(_userdata),
    cfg(_cfg),
    path_found_cb(_cb),
    log("PathFinder")
{
    pool = new WvHttpPool();
    WvIStreamList::globallist.append(pool, false);
    pool->addRef();
}


PathFinder::~PathFinder()
{
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
    path_found_cb(path, err, userdata);
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
        if (!get_crl(cert))
            return;
        get_signer(cert);
        return;
    }
    else if (!trusted_store->exists(cert.get()))
    {
        log("Trust anchor for cert not in store. Attempting to build "
            "bridge.\n");
        path->prepend_cert(cert);        
        if (!create_bridge(cert) || !get_crl(cert))
            return;
        // the process begins again
        return;
    }
    else
    {
        log("Certificate has no non-self signers (and may be a trust anchor). "
            "Stop, perform path validation.\n");
    }

    // otherwise, we've hit a self-signed certificate and are done fetching
    // files to build the path remotely... 

    // try to build a bridge if necessary

    log("Done building path.\n");
    check_done(); // currently 100% probable we don't yet have CRLs
}


bool PathFinder::get_signer(shared_ptr<WvX509> &cert) 
{
    log("Attempting to get signer.\n");

    WvX509Store::WvX509List certlist;
    intermediate_store->get(cert->get_aki(), certlist);
    if (!certlist.empty())
    {
        log("Certificate may be in intermediate store. Checking.\n");
        WvX509Store::WvX509List certlist;
        intermediate_store->get(cert->get_aki(), certlist);

        // prefer one that is self-signed if we have more than one...
        // also disallow certificate's whose issuer matches our subject
        // (we don't want to go around in circles!)
        if (certlist.size() > 1)
        {
            for (WvX509Store::WvX509List::iterator i=certlist.begin();
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

        if (certlist[0]->get_subject() == cert->get_issuer() && 
            certlist[0]->get_issuer() != cert->get_subject() &&
            added_certs.count(certlist[0]->get_subject().cstr()) == 0)
        {
            check_cert(certlist[0]);
            return true;
        }

        log("Could not find certificate in intermediate store matching "
            "issuer name that may not have been previously added.\n");
    }

    WvStringList ca_urls;
    cert->get_ca_urls(ca_urls);

    DownloadFinishedCb cb(this, &PathFinder::signer_download_finished_cb);
    return retrieve_object(ca_urls, cb, NULL);
}


static shared_ptr<WvX509> decode_pkcs7(const unsigned char *buffer, int len)
{
    shared_ptr<WvX509> x;

    PKCS7 *pkcs7;
    STACK_OF(X509) *certs=NULL;
    int i;
    const unsigned char *p = buffer;
    pkcs7 = d2i_PKCS7(NULL, &p, len);

    // If this isn't a valid PKCS7 object... don't return anything
    if (!pkcs7)
	return x;

    i = OBJ_obj2nid(pkcs7->type);
    if (i == NID_pkcs7_signed)
	certs = pkcs7->d.sign->cert;
    else if (i == NID_pkcs7_signedAndEnveloped)
	certs = pkcs7->d.signed_and_enveloped->cert;
    else
	return x;
    
    if (certs != NULL && sk_X509_num(certs) > 0)
    {
        X509 *_x = sk_X509_value(certs, 0);
        x = shared_ptr<WvX509>(new WvX509(X509_dup(_x)));
        printf("Cert %s\n", x->get_subject().cstr());
   }

    return x;
}



void PathFinder::signer_download_finished_cb(WvStringParm urlstr, 
                                             WvStringParm mimetype, WvBuf &buf, 
                                             WvError _err, void *userdata)
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
        shared_ptr<WvX509> cert = decode_pkcs7(buf.get(buf.used()), 
                                                  buf.used());
        check_cert(cert);
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
    vector< boost::shared_ptr<WvX509> > cross_certs;
    intermediate_store->get_cross_certs(cert, cross_certs);

    log("Creating bridge for certificate %s.\n", cert->get_subject());

    // first, attempt to find a cross cert which leads back to a trust anchor
    for (WvX509Store::WvX509List::iterator i = cross_certs.begin(); i != cross_certs.end();
         i++)
    {
        log("Checking cross cert %s (with issuer %s)\n", (*i)->get_subject(), (*i)->get_issuer());

        if (trusted_store->exists((*i)->get_aki()) || 
            (!!cfg["intermediate CAs"].xget((*i)->get_aki()) &&
                1))
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
        added_certs.count(cross_certs[0]->get_ski().cstr()) == 0)
    {
        check_cert(cross_certs[0]);
        return true;
    }
    
    failed("Couldn't find bridge which leads back to trust anchor");
    return false;
}


bool PathFinder::get_crl(shared_ptr<WvX509> &cert)
{
    log("Attempting to get CRL.\n");
    WvStringList crl_urls;
    cert->get_crl_urls(crl_urls);

    if (!crl_urls.count())
    {
        log("No CRL urls for certificate %s. Returning and hoping for "
            "the best.\n", cert->get_subject());
        return true;
    }

    DownloadFinishedCb cb(this, &PathFinder::crl_download_finished_cb);
    return retrieve_object(crl_urls, cb, cert.get());
}


void PathFinder::crl_download_finished_cb(WvStringParm urlstr, 
                                          WvStringParm mimetype, WvBuf &buf, 
                                          WvError _err, void *userdata)
{
    if (_err.geterr())
    {
        failed(WvString("Couldn't download CRL at url %s", urlstr));
        return;
    }

    WvX509 *cert = static_cast<WvX509 *>(userdata);

    log("Got CRL with mimetype %s.\n", mimetype);
    
    shared_ptr<WvCRL> crl(new WvCRL);
    if (!strncmp("-----BEGIN", (const char *) buf.peek(0, 10), 10))
        crl->decode(WvCRL::CRLPEM, buf);
    else
        crl->decode(WvCRL::CRLDER, buf); 
    path->add_crl(cert->get_ski(), crl);

    check_done();
}


bool PathFinder::retrieve_object(WvStringList &_urls, DownloadFinishedCb _cb,
                                 void *_userdata)
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
            shared_ptr<Downloader> d(new Downloader(url, pool, _cb, 
                                                           _userdata));
            downloaders.push_back(d);
            d->download();    
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
    for (DownloaderList::iterator i = downloaders.begin();
         i != downloaders.end(); i++)
    {
        if (!(*i)->is_done())
            return;
    }

    log("All objects needed to validate path have been put into place. We "
        "are done\n");
    path_found_cb(path, err, userdata);
}
