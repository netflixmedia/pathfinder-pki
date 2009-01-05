/*
 * downloader.h
 *
 * Copyright (C) 2007-2009 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#ifndef __DOWNLOADER_H
#define __DOWNLOADER_H
#include <wvbuf.h>
#include <wverror.h>
#include <wvhttppool.h>
#include <wvlog.h>
#include <wvstream.h>
#include <xplc/ptr.h>


typedef wv::function<void(WvStringParm, WvStringParm, WvBuf&, WvError)> DownloadFinishedCb;

class Downloader
{
  public:
    Downloader(WvStringParm _url, WvHttpPool *_pool, 
               DownloadFinishedCb _cb,
               WvStringParm _method = "GET",
               WvStringParm _headers = "",
               WvStream *content_source = NULL);
    virtual ~Downloader();
    bool is_done() { return done; }

  private:
    WvDynBuf downloadbuf;
    void download_cb(WvStream &s);
    void download_closed_cb(WvStream &s);

    WvString url;
    WvHttpPool *pool;
    xplc_ptr<WvBufUrlStream> stream;
    DownloadFinishedCb finished_cb;
    bool done;
    WvLog log;
};

#endif
