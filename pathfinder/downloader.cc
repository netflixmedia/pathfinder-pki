/*
 * downloader.cc
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */


#include <wvhttppool.h>
#include <wvistreamlist.h>
#include <wvstrutils.h>
#include <ldap.h>

#include "downloader.h"

Downloader::Downloader(WvStringParm _url, WvHttpPool *_pool, 
                       DownloadFinishedCb _cb,
                       WvStringParm _method,
                       WvStringParm _headers,
                       WvStream *_content_source) :
    url(_url),
    pool(_pool),
    finished_cb(_cb),
    done(false),
    log(WvString("Pathfinder Download:", url), WvLog::Info)
{
    log("Downloading: %s\n", url);
    WvStringList l;
    strcoll_split(l, url, ":");
    WvString proto = l.popstr();
    log("Protocol is: %s\n", proto);
        
    if (proto == "http" || proto == "https")
    {
        log("Kicking off download of %s.\n", url);
        stream = pool->addurl(url, _method, _headers, _content_source);
        stream->setcallback(wv::bind(&Downloader::download_cb, this, 
                                     wv::ref(*stream)));
        stream->setclosecallback(wv::bind(&Downloader::download_closed_cb, this, 
                                          wv::ref(*stream)));
        WvIStreamList::globallist.append(stream, true, WvString("download url %s", 
                                                                 url));
    }
    else if (proto == "ldap" || proto == "ldaps")
    {
        download_ldap();    
    }
    else
    {
        WvError err;    
        WvString mimetype = WvString::null;
        err.seterr("Unrecognised protocol... dying");
        done = true;
        if (finished_cb)
            finished_cb(url, mimetype, downloadbuf, err);
    }
}


Downloader::~Downloader()
{   
    if (stream)
    {
        stream->setcallback(0);
        stream->setclosecallback(0);
    }
}


void Downloader::download_cb(WvStream &s)
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
        log("Didn't download %s successfully (%s).\n", url, s.errstr());
        err.seterr_both(s.geterr(), s.errstr());
        if (finished_cb)
            finished_cb(url, mimetype, downloadbuf, err);
        return;
    }
    WvHTTPHeaderDict::Iter i(stream->headers);
    for (i.rewind(); i.next(); )
    {
        if (!strcasecmp(i->name, "Content-Type"))
        {
            mimetype = i->value;
            break;
        }
    }

#ifndef WVHTTPPOOLFIXED
    if (!downloadbuf.used())
        err.seterr("Didn't download %s successfully.", url);
#endif

    done = true;
    if (finished_cb)
        finished_cb(url, mimetype, downloadbuf, err);
}

void Downloader::download_ldap()
{
    WvDynBuf buf;
    WvError err;
    WvString mimetype = WvString::null;

    log("Found an LDAP URI: %s\n", url);
    if (strncmp(url,"ldaps", 5) == 0)      
    {
        log("Sorry, don't know how to handle LDAP over SSL yet.\n");
    }
    else
    {
        LDAPURLDesc *lurl = NULL;
        int retval = ldap_url_parse(WvString(url), &lurl);
        if (retval == LDAP_SUCCESS)
        {
            log(WvLog::Debug5,"Host name: %s\n"
                "DN: %s\nATTR: %s\n", 
                lurl->lud_host, lurl->lud_dn, 
                lurl->lud_attrs ? lurl->lud_attrs[0] : "none");
            LDAP *ldap = NULL;
            retval = ldap_initialize(&ldap, WvString(url));
            if (retval == LDAP_SUCCESS)                        
            {
                log(WvLog::Debug5, "LDAP initialized..\n");         
                LDAPMessage *res = NULL;
                retval = ldap_search_ext_s(ldap, lurl->lud_dn,
                        lurl->lud_scope,
                        lurl->lud_filter,
                        lurl->lud_attrs, 
                        0, NULL, NULL, NULL, 0, &res);
                WvString attr(lurl->lud_attrs[0]);
                ldap_free_urldesc(lurl);
                if (retval == LDAP_SUCCESS)
                {
                    log(WvLog::Debug5, "LDAP Search succeeded...\n");
                    retval = ldap_count_messages(ldap, res);
                    if (retval == 1 || true)                        
                    {               
                        LDAPMessage *entry = NULL;
                        entry = ldap_first_entry(ldap, res);
                        if (entry)
                        {
                            struct berval **val = NULL;       
                            if (attr == "cACertificate;binary" || 
                                attr == "certificateRevocationList;binary")
                            {                                                               
                                log(WvLog::Debug5, "We've got a CA Cert or CRL.\n");
                                val = ldap_get_values_len(ldap, entry, attr);
                                if (val)
                                {
#if 0
                                    if (ldap_count_values(val) > 1)
                                        log(WvLog::Info, 
                                            "Strange - more than one entry returned for %s.\n"
                                            "Using only the first value!\n", attr);
#endif
                                    buf.put(val[0]->bv_val, val[0]->bv_len);
                                    log(WvLog::Debug5, "Response was %s bytes long.\n",
                                        buf.used());
                                    ldap_value_free_len(val);
                                    ldap_msgfree(res);
                                    ldap_unbind_ext(ldap, NULL, NULL);
                                    done = true;
                                    if (finished_cb)
                                        finished_cb(url, mimetype, buf, err);

                                    return;
                                }
                                else
                                {
                                    int ov;
                                    ldap_get_option(ldap, LDAP_OPT_RESULT_CODE, &ov);
                                    BerElement **bel = NULL;
                                    log(WvLog::Critical, "Attribute was: %s\n",
                                        ldap_first_attribute(ldap, res, bel));
                                    log(WvLog::Critical, "Error getting value for %s (%s)!\n",
                                        attr, 
                                        ldap_err2string(ov));
                                    ldap_msgfree(res);       
                                    ldap_unbind_ext(ldap, NULL, NULL);
                                }
                            }
                            else
                            {
                                log(WvLog::Info, 
                                    "I don't know how to process the attribute: %s\n", 
                                    attr); 
                                ldap_msgfree(res);
                                ldap_unbind_ext(ldap, NULL, NULL);
                            }
                        }
                        else
                        {
                            int ov;
                            ldap_get_option(ldap, LDAP_OPT_RESULT_CODE, &ov);
                            log(WvLog::Critical, "No entry?? (%s)\n", ldap_err2string(ov));
                            ldap_msgfree(res);
                            ldap_unbind_ext(ldap, NULL, NULL);
                        }                                            
                    }
                    else
                    {
                        log("LDAP Search returned more than one value (%s),"
                            "which is not permitted.\n", retval);
                        ldap_msgfree(res);
                        ldap_unbind_ext(ldap, NULL, NULL);
                    }
                }
                else
                {
                    log(WvLog::Info, "LDAP Search failed: %s\n", 
                        ldap_err2string(retval));
                    ldap_msgfree(res);
                    ldap_unbind_ext(ldap, NULL, NULL);
                } 
            }
            else
            {
                log(WvLog::Critical, "LDAP could not initialize: %s\n", 
                    ldap_err2string(retval));
                if(ldap)
                    ldap_unbind_ext(ldap, NULL, NULL);
            }
        }
        else
        {
            ldap_free_urldesc(lurl);
            log(WvLog::Critical, "LDAP URL could not be parsed: %s.\n", 
                ldap_err2string(retval));
        }
    }
    err.seterr("LDAP download failed!");
    done = true;
    if (finished_cb)
        finished_cb(url, mimetype, buf, err);
    return;
}
