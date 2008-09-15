/*
 * pathfinder.h
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#ifndef __PATHFINDER_H
#define __PATHFINDER_H
#include <boost/shared_ptr.hpp>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <uniconf.h>
#include <vector>
#include <wvhttppool.h>
#include <wvx509.h>

#include "downloader.h"
#include "wvx509path.h"
#include "wvx509store.h"

typedef wv::function<void(boost::shared_ptr<WvX509Path> &, WvError, void *)> PathFoundCb;

class PathFinder
{
public:
    PathFinder(boost::shared_ptr<WvX509> &_cert,
               boost::shared_ptr<WvX509Store> &_trusted_store,
               boost::shared_ptr<WvX509Store> &_intermediate_store,
               uint32_t _validation_flags,
               UniConf &_cfg, 
               PathFoundCb _cb, void *_userdata);
    
    virtual ~PathFinder(); 
    WvString cert_ski() { return cert_to_be_validated->get_ski(); }

    void find();

  private:
    void check_cert(boost::shared_ptr<WvX509> &cert);
    void failed(WvStringParm reason);
    void failed();
    
    bool get_signer(boost::shared_ptr<WvX509> &cert);
    void signer_download_finished_cb(WvStringParm urlstr, WvStringParm mimetype, 
                                     WvBuf &buf, WvError _err, void *userdata);
    
    bool get_crl(boost::shared_ptr<WvX509> &cert);
    void crl_download_finished_cb(WvStringParm urlstr, WvStringParm mimetype, 
                                  WvBuf &buf, WvError _err, void *userdata);
    
    bool retrieve_object(WvStringList &_urls, DownloadFinishedCb _cb, 
                         void *_userdata);


    bool create_bridge(boost::shared_ptr<WvX509> &cert);

    void check_done();

    boost::shared_ptr<WvX509> cert_to_be_validated;
    boost::shared_ptr<WvX509Store> trusted_store;
    boost::shared_ptr<WvX509Store> intermediate_store;

    uint32_t validation_flags;

    boost::shared_ptr<WvX509> curcert; // cert we are currently working on
    boost::shared_ptr<WvX509Path> path;
    std::map<std::string, bool> added_certs;

    typedef std::vector<boost::shared_ptr<Downloader> > DownloaderList;
    DownloaderList downloaders;

    WvHttpPool *pool;

    void *userdata;
    PathFoundCb path_found_cb;
    UniConf cfg;
    WvError err;
    WvLog log;
};


#endif // __PATHFINDER_H
    
