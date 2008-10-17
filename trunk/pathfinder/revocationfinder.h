/*
 * revocationfinder.h
 *
 * Copyright (C) 2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#ifndef __REVOCATIONFINDER_H
#define __REVOCATIONFINDER_H
#include <boost/shared_ptr.hpp>
#include <uniconf.h>
#include <vector>
#include <wvhttppool.h>
#include <wvx509.h>

#include "downloader.h"
#include "wvx509path.h"
#include "wvcrlcache.h"


typedef wv::function<void(WvError)> FoundRevocationInfoCb;

// FIXME: this class has a ton of duplication with PathFinder and Downloader.
// Need to find a way of factoring out all the commonalities into a seperate 
// class.
class RevocationFinder
{
  public:
    RevocationFinder(boost::shared_ptr<WvX509> &_cert, 
                     boost::shared_ptr<WvX509> &_issuer, 
                     boost::shared_ptr<WvX509Path> &_path, 
                     boost::shared_ptr<WvCRLCache> &_crlcache,
                     bool _check_ocsp,
                     UniConf &_cfg,
                     FoundRevocationInfoCb _cb);
    virtual ~RevocationFinder();
    
    bool is_done() { return done; }

  private:
    void find();

    void failed(WvStringParm reason);
    void failed();
    void try_download_next();
    bool retrieve_object_http(WvStringParm _url, DownloadFinishedCb _cb,
                              WvStringParm _method = "GET",
                              WvStringParm _headers = "",
                              WvStream *content_source = NULL);
    void crl_download_finished_cb(WvStringParm urlstr, 
                                  WvStringParm mimetype, 
                                  WvBuf &buf, 
                                  WvError _err);
    void ocsp_download_finished_cb(WvStringParm urlstr, 
                                   WvStringParm mimetype, 
                                   WvBuf &buf, 
                                   WvError _err,
                                   boost::shared_ptr<WvOCSPReq> &req);

    boost::shared_ptr<WvX509> cert;
    boost::shared_ptr<WvX509> issuer;
    boost::shared_ptr<WvCRLCache> crlcache;
    WvStringList ocsp_urls;
    WvStringList crl_urls;

    boost::shared_ptr<WvX509Path> path;

    WvHttpPool *pool;
    typedef std::vector<boost::shared_ptr<Downloader> > DownloaderList;
    DownloaderList downloaders;
    bool done;

    bool check_ocsp;
    UniConf cfg;

    FoundRevocationInfoCb cb;
    WvError err;
    WvLog log;
};

#endif // _REVOCATIONFINDER_H

