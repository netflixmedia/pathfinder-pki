/*
 * revocationfinder.cc
 *
 * Copyright (C) 2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <wvbufstream.h>
#include <wvocsp.h>
#include <wvstrutils.h>
#include "revocationfinder.h"

using namespace boost;


RevocationFinder::RevocationFinder(shared_ptr<WvX509> &_cert, 
                                   shared_ptr<WvX509> &_issuer, 
                                   shared_ptr<WvX509Path> &_path,
                                   shared_ptr<WvCRLCache> &_crlcache,
                                   UniConf &_cfg,
                                   FoundRevocationInfoCb _cb) :
    cfg(_cfg),
    log(WvString("Revocation Finder for %s", _cert->get_subject()), 
        WvLog::Debug1)
{
    pool = new WvHttpPool();
    WvIStreamList::globallist.append(pool, false, 
                                     "revocation finder http pool");
    cert = _cert;
    issuer = _issuer;
    path = _path;
    crlcache = _crlcache;
    cb = _cb;
    done = false;

    find();
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
    WvString hardcoded_crl_loc = cfg["CRL Location"].xget(
        url_encode(cert->get_subject()));
    if (!!hardcoded_crl_loc)
    {
        WvUrl url(hardcoded_crl_loc);
        if (url.getproto() == "http" || url.getproto() == "https")
        {
            DownloadFinishedCb cb = wv::bind(
                &RevocationFinder::crl_download_finished_cb, 
                this, _1, _2, _3, _4);
            if (retrieve_object_http(hardcoded_crl_loc, cb))
                return;
        }
        else if (url.getproto() == "file")
        {
            WvString crlpath = url.getfile();

            shared_ptr<WvCRL> crl(new WvCRL);
            crl->decode(WvCRL::CRLFilePEM, crlpath);
            if (!crl->isok()) 
                crl->decode(WvCRL::CRLFileDER, crlpath);
            
            if (!crl->isok())
            {
                failed(WvString("Explicitly defined CRL for certificate (in "
                                "file %s, but CRL not ok", crlpath));
                return;
            }
                
            path->add_crl(cert->get_subject(), crl);
            
            done = true;
            cb(err);
            return;
        }
    }

    // try to grab both crl and OCSP info
    cert->get_ocsp(ocsp_urls);
    cert->get_crl_urls(crl_urls);

    if (!crl_urls.count() && !ocsp_urls.count())
    {
        log("No revocation info for certificate %s.\n", cert->get_subject());
        failed("No revocation info");
        return;
    }

    WvStringList::Iter i(crl_urls);
    for (i.rewind(); i.next();)
    {
        WvUrl url(i());
        if (crlcache->exists(url)) // FIXME: and the crl hasn't expired yet...
        {            
            log("Found url %s in crlcache, no need to download CRL.\n", url);
            shared_ptr<WvCRL> crl = crlcache->get(url);
            path->add_crl(cert->get_subject(), crl);

            done = true;
            cb(err);
            return;
        }
    }

    // otherwise, we gotta download stuff
    log("No ready revocation info in cache for certificate %s. Proceeding to "
        "download...\n", cert->get_subject());
        
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
    while (ocsp_urls.count())
    {
        // create ocsp request, put it in a stream so we can send it to
        // the server
        shared_ptr<WvOCSPReq> req(new WvOCSPReq(*cert, *issuer));
        WvDynBuf reqbuf;
        req->encode(reqbuf);
        WvBufStream *input_stream = new WvBufStream;
        input_stream->write(reqbuf, reqbuf.used());
        WvIStreamList::globallist.append(input_stream, true, 
                                         "OCSP Request Buffer Stream");

        DownloadFinishedCb cb = wv::bind(
            &RevocationFinder::ocsp_download_finished_cb, 
            this, _1, _2, _3, _4, req);
        if (retrieve_object_http(ocsp_urls.popstr(), cb, "POST", 
                            "Content-Type: application/ocsp-request\r\n",
                            input_stream))
            return;
    }

    while (crl_urls.count())
    {    
        DownloadFinishedCb cb = wv::bind(
            &RevocationFinder::crl_download_finished_cb, 
            this, _1, _2, _3, _4);
        if (retrieve_object_http(crl_urls.popstr(), cb))
            return;
    }

    failed("Couldn't retrieve revocation info");
}


bool RevocationFinder::retrieve_object_http(WvStringParm _url, 
                                            DownloadFinishedCb _cb,
                                            WvStringParm _method,
                                            WvStringParm _headers,
                                            WvStream *_content_source)
{
    log("Attempting to retrieve revocation object at URL %s.\n", _url);
    
    WvUrl url(_url);
    if (url.getproto() == "http" || url.getproto() == "https")
    {
        shared_ptr<Downloader> d(new Downloader(url, pool, _cb, _method, 
                                                _headers, _content_source));
        downloaders.push_back(d);
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
    crlcache->add(urlstr, buf);

    path->add_crl(cert->get_subject(), crl);

    done = true;
    cb(err);
}


void RevocationFinder::ocsp_download_finished_cb(WvStringParm urlstr, 
                                                 WvStringParm mimetype, 
                                                 WvBuf &buf, 
                                                 WvError _err,
                                                 shared_ptr<WvOCSPReq> &req)
{
    if (_err.geterr())
    {
        log("Couldn't download OCSP response at url %s\n", urlstr);
        try_download_next();
        
        return;
    }

    log("Got OCSP with mimetype %s.\n", mimetype);

    shared_ptr<WvOCSPResp> resp(new WvOCSPResp);
    resp->decode(buf);

    if (!resp->isok())
    {
        log("OCSP response downloaded from %s is not ok!\n", urlstr);
        try_download_next();

        return;
    }

    if (!resp->check_nonce(*req))
    {
        log("OCSP nonce for response downloaded from %s not ok!\n", urlstr);
        try_download_next();

        return;
    }

    path->add_ocsp_resp(cert->get_subject(), resp);

    done = true;
    cb(err);
}
