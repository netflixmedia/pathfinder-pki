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
#include "util.h"

using namespace boost;


RevocationFinder::RevocationFinder(shared_ptr<WvX509> &_cert, 
                                   shared_ptr<WvX509> &_issuer, 
                                   shared_ptr<WvX509Path> &_path,
                                   shared_ptr<WvCRLCache> &_crlcache,
                                   bool _check_ocsp,
                                   UniConf &_cfg,
                                   FoundRevocationInfoCb _cb) :
    check_ocsp(_check_ocsp),
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

    //find();
}


RevocationFinder::~RevocationFinder()
{
    WvIStreamList::globallist.unlink(pool);
    WVRELEASE(pool);
}


void RevocationFinder::find()
{    
    int only_ocsp = cfg["Verification Options"].xgetint("Use OCSP", 1);
    // Only get all of the CRL information if we have been told not to use
    // OCSP exclusively. We're using != 2 here since we want to treat *ANY*
    // value other than 2 as 1, and 0 was caught over in pathfinder.cc,
    // making check_ocsp here false.
    if (only_ocsp != 2)
    {
        // first, check to see if we have a CRL explicitly defined for this
        // certificate's issuer
        WvString hardcoded_crl_loc = cfg["CRL Location"].xget(
                                    url_encode(cert->get_issuer(), "/="));
        if (!!hardcoded_crl_loc)
        {
            shared_ptr<WvCRL> crl = crlcache->get_file(hardcoded_crl_loc);
            if (crl && !crl->expired())
            {
                path->add_crl(cert->get_subject(), crl);
                done = true;
                log("Got CRL from hardcoded location.\n");
                cb(err);
                return;
            }
        }
    }

    // try to grab both crl and OCSP info (the latter only if we're checking 
    // ocsp, and the former only if CRL check is not excluded)
    if (check_ocsp)
        cert->get_ocsp(ocsp_urls);
    
    if (only_ocsp != 2)
        cert->get_crl_urls(crl_urls);

    if (!crl_urls.count() && !ocsp_urls.count())
    {
        log("No revocation info for certificate %s.\n", cert->get_subject());
        failed("No revocation info");
        return;
    }

    // And here, only sort the CRL DP's and check the cache if we DO want to
    // check CRL information.
    if (only_ocsp != 2)
    {
        if (cfg["General"].xgetint("Prefer LDAP"))
            sort_urls(crl_urls, true);          
        else 
            sort_urls(crl_urls, false);    

        WvStringList::Iter i(crl_urls);
        for (i.rewind(); i.next();)
        {
            WvUrl url(i());

            shared_ptr<WvCRL> crl = crlcache->get_url(url);
            if (crl && !crl->expired())
            {
                path->add_crl(cert->get_subject(), crl);
                done = true;
                log("Got CRL from cache.\n");
                cb(err);
                return;
            }
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
    
    WvUrl tmpurl(_url);
    WvString newurl(_url);
    if (tmpurl.getproto() == "http" || tmpurl.getproto() == "https")
    {
        WvString hproxy = cfg["General"].xget("HTTP Proxy");
        if (!!hproxy)
        {
            log(WvLog::Info, "Using '%s' as the HTTP Proxy!\n", hproxy);
            WvUrl nurl(rewrite_url(tmpurl, hproxy));
            newurl = nurl;
        }
    }
    else if (tmpurl.getproto() == "ldap")
    {
        WvString lproxy = cfg["General"].xget("LDAP Proxy");
        if (!!lproxy)
        {
            log(WvLog::Info, "Using '%s' as the LDAP Proxy!\n", lproxy);
            WvUrl nurl(rewrite_url(tmpurl, lproxy));
            newurl = nurl;
        }
    }
    else
    {
        log("Protocol %s not supported for getting object.\n", 
            tmpurl.getproto());
        return false;
    }

    WvUrl url(newurl);
    shared_ptr<Downloader> d(new Downloader(url, pool, _cb, _method, 
                                            _headers, _content_source));
    downloaders.push_back(d);
    return true;
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
    if (guess_encoding(buf) == WvX509::CertPEM)
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

    WvOCSPResp::Status status = resp->get_status(*cert, *issuer);
    if (status == WvOCSPResp::Error || status == WvOCSPResp::Unknown)
    {
        log("OCSP response isn't canonical (status: %s).  Falling back "
            "to CRL, if available.\n", WvOCSPResp::status_str(status));
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
