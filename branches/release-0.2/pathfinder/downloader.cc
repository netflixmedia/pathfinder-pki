/*
 * downloader.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include <wvhttppool.h>
#include <wvistreamlist.h>

#include "downloader.h"

Downloader::Downloader(WvStringParm _url, WvHttpPool *_pool, 
                       DownloadFinishedCb _cb, void *_userdata) :
    url(_url),
    pool(_pool),
    finished_cb(_cb),
    userdata(_userdata),
    done(false),
    log("Pathfinder Download", WvLog::Debug5)
{
}


Downloader::~Downloader()
{   
    if (stream)
    {
        stream->setcallback(WvStreamCallback(), NULL);
        stream->setclosecallback(IWvStreamCallback());
    }
}


void Downloader::download()
{
    log("Downloading.\n");
    stream = pool->addurl(url);
    stream->setcallback(WvStreamCallback(this, &Downloader::download_cb), NULL);
    stream->setclosecallback(IWvStreamCallback(this, 
                                          &Downloader::download_closed_cb));
    WvIStreamList::globallist.append(stream, true, WvString("download url %s", url));
}


void Downloader::download_cb(WvStream &s, void *)
{
    char buf[1024];
    size_t numread = 0;
    size_t totalread = 0;
    while (s.isreadable() && totalread < 32768)
    {
        numread = s.read(buf, 1024);
        if (numread)
            downloadbuf.put(buf, numread);
        totalread += numread;
    }
}


void Downloader::download_closed_cb(WvStream &s)
{
    WvError err;    
    WvString mimetype = WvString::null;

    // as of this writing, errors are not properly set on a urlstream
    // when there's a problem, so we have to resort to hacks to validate stuff
#if WVHTTPPOOLFIXED
    if (!s.isok() && s.geterr())
#else
    if (0)
#endif
    {
        log("Didn't download item successfully (%s).\n", s.errstr());
        err.seterr_both(s.geterr(), s.errstr());
        finished_cb(url, mimetype, downloadbuf, err, userdata);
        return;
    }
    WvHTTPHeaderDict::Iter i(stream->headers);
    for (i.rewind(); i.next(); )
    {
        if (i->name == "Content-Type")
        {
            mimetype = i->value;
            break;
        }
    }

#ifndef WVHTTPPOOLFIXED
    if (!downloadbuf.used())
        err.seterr("Didn't download item successfully.");
#endif

    done = true;
    finished_cb(url, mimetype, downloadbuf, err, userdata);
}