/*
 * revocationfinder.cc
 *
 * Copyright (C) 2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include "revocationfinder.h"


using namespace boost;


RevocationFinder::RevocationFinder(shared_ptr<WvX509> &_cert, 
                                   shared_ptr<WvX509Path> &_path,
                                   shared_ptr<WvCRLStore> &_crlstore,
                                   FoundRevocationInfoCb _cb) :
    log(WvString("Revocation Finder for %s", _cert->get_subject()), 
        WvLog::Debug1)
{
    pool = new WvHttpPool();
    WvIStreamList::globallist.append(pool, false, "revocationfinder http pool");
    cert = _cert;
    path = _path;
    crlstore = _crlstore;
    cb = _cb;
    done = false;
}


RevocationFinder::~RevocationFinder()
{
    WvIStreamList::globallist.unlink(pool);
    WVRELEASE(pool);
}


void RevocationFinder::find()
{
    // first, check to see if we have a CRL explicitly defined for this
    // certificate
    // FIXME: todo

    // next, try to get ocsp info. it's faster to grab and fresher than a CRL
#if 0
    log("Checking for OCSP info.\n");
    WvStringList ocsp_urls;
    cert.get_ocsp(ocsp_urls);
#endif

    cert->get_crl_urls(crl_urls);

    if (!crl_urls.count() /* && */)
    {
        log("No revocation info for certificate %s", cert->get_subject());
        failed("No revocation info");
        return;
    }

    WvStringList::Iter i(crl_urls);
    for (i.rewind(); i.next();)
    {
        WvUrl url(i());
        if (crlstore->exists(url)) // FIXME: and the crl hasn't expired yet...
        {            
            log("Found url %s in crlstore, no need to download CRL.\n", url);
            shared_ptr<WvCRL> crl= crlstore->get(url);
            path->add_crl(cert->get_ski(), crl);

            done = true;
            cb(err);
            return; 
        }
    }

    // otherwise, we gotta download stuff
    try_download_next();
}


void RevocationFinder::failed(WvStringParm reason)
{
    err.seterr(reason);
    failed();
}


void RevocationFinder::failed()
{
    done = true;
    cb(err);
}


void RevocationFinder::try_download_next()
{
    while (crl_urls.count())
    {    
        DownloadFinishedCb cb = wv::bind(
            &RevocationFinder::crl_download_finished_cb, 
            this, _1, _2, _3, _4);
        if (retrieve_object(crl_urls.popstr(), cb))
            return;
    }

    failed("Couldn't retrieve revocation info");
}


bool RevocationFinder::retrieve_object(WvStringParm _url, 
                                       DownloadFinishedCb _cb)
{
    WvUrl url(_url);
    if (url.getproto() == "http" || url.getproto() == "https")
    {
        shared_ptr<Downloader> d(new Downloader(url, pool, _cb));
        downloaders.push_back(d);
        d->download();
        return true;
    }
    else
        log("Protocol %s not supported for getting object.\n", 
            url.getproto());

    return false;
}


void RevocationFinder::crl_download_finished_cb(WvStringParm urlstr, 
                                                WvStringParm mimetype, 
                                                WvBuf &buf, 
                                                WvError _err)
{
    if (_err.geterr())
    {
        log("Couldn't download CRL at url %s\n", urlstr);
        try_download_next();
        
        return;
    }

    log("Got CRL with mimetype %s.\n", mimetype);
       
    shared_ptr<WvCRL> crl(new WvCRL);
    if (!strncmp("-----BEGIN", (const char *) buf.peek(0, 10), 10))
        crl->decode(WvCRL::CRLPEM, buf);
    else
        crl->decode(WvCRL::CRLDER, buf);

    if (!crl->isok())
    {
        log("CRL downloaded from url %s is not ok!", urlstr);
        try_download_next();

        return;
    }

    // we could check to see if the CRL is signed by the appropriate
    // person and that it hasn't expired here, but that seems like overkill
    // to me. if you're putting up a CRL somewhere, make sure that it's valid!

    // crl is ok, (re) add it to our store
    buf.unget(buf.ungettable());
    crlstore->add(urlstr, buf);

    path->add_crl(cert->get_ski(), crl);

    done = true;
    cb(err);
}
