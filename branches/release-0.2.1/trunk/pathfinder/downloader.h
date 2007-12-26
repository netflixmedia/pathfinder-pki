/*
 * downloader.h
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
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


typedef WvCallback<void, WvStringParm, WvStringParm, WvBuf&, 
    WvError, void*> DownloadFinishedCb;

class Downloader
{
  public:
    Downloader(WvStringParm _url, WvHttpPool *_pool, DownloadFinishedCb _cb, 
               void *_userdata);
    virtual ~Downloader();
    void download();
    bool is_done() { return done; }

  private:
    WvDynBuf downloadbuf;
    void download_cb(WvStream &s, void *);
    void download_closed_cb(WvStream &s);

    WvString url;
    WvHttpPool *pool;
    xplc_ptr<WvBufUrlStream> stream;
    DownloadFinishedCb finished_cb;
    void *userdata;
    bool done;
    WvLog log;
};

#endif
