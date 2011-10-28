/*
 * util.cc
 *
 * Copyright (C) 2008-2011 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <wvfile.h>
#include <wvurl.h>
#include <wvregex.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <assert.h>
#include "util.h"

using namespace boost;

WvX509::DumpMode guess_encoding(WvBuf &buf)
{
    if (buf.used() < 10)
        return WvX509::CertDER;

    if (!strncmp("-----BEGIN", (const char *) buf.peek(0, 10), 10))
        return WvX509::CertPEM;

    return WvX509::CertDER;
}


WvX509::DumpMode guess_encoding(WvStringParm fname)
{
    WvFile f(fname, O_RDONLY);
    WvDynBuf buf;
    size_t read = f.read(buf, 10);

    WvX509::DumpMode mode = guess_encoding(buf);
    if (mode == WvX509::CertPEM)
        return WvX509::CertFilePEM;

    return WvX509::CertFileDER;
}

bool is_md(shared_ptr<WvX509> &x509)
{	
    X509 *cert = x509->get_cert();
    int alg = OBJ_obj2nid(cert->sig_alg->algorithm);
    
    if (alg == NID_md5WithRSAEncryption || alg == NID_md2WithRSAEncryption)
        return true;
      
    return false;
}

size_t get_keysize(shared_ptr<WvX509> &x509)
{
    EVP_PKEY *p = X509_get_pubkey(x509->get_cert());

    // FIXME: this only supports RSA for now.
    if (p && p->type == EVP_PKEY_RSA)
        return BN_num_bits(p->pkey.rsa->n);
    return 0;
}

#if 0
bool is_valid_host(WvStringParm hostname_or_ip)
{
// If and when WvRegex ever grows more intelligence... do this.
    WvRegex r("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\\."
              "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$");
    WvString match;
    r.match(hostname_or_ip, match);
    if (hostname_or_ip == match)
    {
        // This was an IP Address
        return true;
    }
    r.set("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*"
          "([A-Za-z]|[A-Za-z][A-Za-z0-9\\-]*[A-Za-z0-9])$");
    r.match(hostname_or_ip, match);
    if (!!match)
        return true;
    else
        return false;
}
#endif

WvUrl rewrite_url(WvUrl url, WvStringParm hostname_or_ip)
{

    // This isn't as generic as I would like, but it's better than nothing.
    WvString newurl;
    newurl.append(url.getproto());
    newurl.append("://");
    newurl.append(hostname_or_ip);
    newurl.append(url.getfile());

    return WvUrl(newurl);
} 

void sort_urls(WvStringList &urllist, bool ldap_first)
{
    WvStringList llist, hlist, olist;
    while (urllist.count())
    {
        WvUrl url(urllist.popstr());
        if (url.getproto() == "ldap")
            llist.append(url);
        else if (url.getproto() == "http" ||
                 url.getproto() == "https") 
            hlist.append(url);
        else
            olist.append(url);
    }

    if (ldap_first)
    {
        while (llist.count())
            urllist.append(llist.popstr());
        while (hlist.count())
            urllist.append(hlist.popstr());
    }
    else
    {
        while (hlist.count())
            urllist.append(hlist.popstr());
        while (llist.count())
            urllist.append(llist.popstr());
    }
    while (olist.count())
        urllist.append(olist.popstr());

    return;
}
