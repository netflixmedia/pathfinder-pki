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
#include <vector>
#include <wvhttppool.h>
#include <wvx509.h>

#include "downloader.h"
#include "wvx509path.h"
#include "wvcrlstore.h"


typedef wv::function<void(WvError)> FoundRevocationInfoCb;

class RevocationFinder
{
  public:
    RevocationFinder(boost::shared_ptr<WvX509> &_cert, 
                     boost::shared_ptr<WvX509Path> &_path, 
                     boost::shared_ptr<WvCRLStore> &_crlstore,
                     FoundRevocationInfoCb _cb);
    virtual ~RevocationFinder();
    
    void find();

  private:

    void failed(WvStringParm reason);
    void failed();
    void try_download_next();
    bool retrieve_object(WvStringParm _url, DownloadFinishedCb _cb);
    void crl_download_finished_cb(WvStringParm urlstr, 
                                  WvStringParm mimetype, 
                                  WvBuf &buf, 
                                  WvError _err);

    boost::shared_ptr<WvX509> cert;
    boost::shared_ptr<WvCRLStore> crlstore;
    WvStringList ocsp_urls;
    WvStringList crl_urls;

    boost::shared_ptr<WvX509Path> path;

    WvHttpPool *pool;
    typedef std::vector<boost::shared_ptr<Downloader> > DownloaderList;
    DownloaderList downloaders;

    FoundRevocationInfoCb cb;
    WvError err;
    WvLog log;
};

#endif // _REVOCATIONFINDER_H

