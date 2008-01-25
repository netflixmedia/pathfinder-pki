/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007, Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */ 
#include "wvdiriter.h"
#include "wvx509store.h"
#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>

using namespace std;
using namespace boost;


WvX509Store::WvX509Store() :
    log("WvX509Store", WvLog::Debug5)
{
}


WvX509Store::~WvX509Store()
{
}


void WvX509Store::load(WvStringParm _dir)
{
    log("Loading store from directory %s.\n", _dir);
    WvDirIter d(_dir, false);
    for (d.rewind(); d.next();)
    {
        if (S_ISREG(d().st_mode))
            add_file(d().fullname);
    }
}


void WvX509Store::add_cert(shared_ptr<WvX509> &x)
{
    certmap.insert(CertPair(x->get_ski().cstr(), x));
}


void WvX509Store::add_file(WvStringParm _fname)
{
    shared_ptr<WvX509> x(new WvX509);
    x->decode(WvX509::CertFilePEM, _fname);
    if (!x->isok()) 
        x->decode(WvX509::CertFileDER, _fname);
    
    if (!x->isok())
    {
        log(WvLog::Warning, "WARNING: Tried to add certificate from file %s, "
            "but loaded certificate not ok!\n", _fname);
        return;
    }
    else if (!x->get_ski())
    {
        log(WvLog::Warning, "WARNING: Tried to add certificate from file %s, "
            "but loaded certificate has no ski!\n", _fname);
        return;
    }
    
    log("Loaded certificate from file %s into store (ski: %s).\n", _fname, 
        x->get_ski());
    certmap.insert(CertPair(x->get_ski().cstr(), x));
}


void WvX509Store::add_pkcs7(WvStringParm _fname)
{
    log("Opening pkcs7 %s.\n", _fname);
    FILE *fp = fopen(_fname, "r");
    if (!fp)
    {
        log(WvLog::Warning, "Could not open file %s.\n", _fname);
        return;
    }

    log("Loading bridgefile.\n");
    PKCS7 *pkcs7 = NULL;
    pkcs7 = d2i_PKCS7_fp(fp, &pkcs7);
    fclose(fp);
    log("Loaded bridgefile.\n");
    
    if (!pkcs7)
    {
        log(WvLog::Warning, WvString("Could not open PKCS7 bridge from file %s.", 
                                     _fname));
        return;
    }
    
    STACK_OF(X509) *certs=NULL;
    int i = OBJ_obj2nid(pkcs7->type);
    if (i == NID_pkcs7_signed)
        certs = pkcs7->d.sign->cert;
    else if (i == NID_pkcs7_signedAndEnveloped)
        certs = pkcs7->d.signed_and_enveloped->cert;
    else
    {
        log(WvLog::Warning, "Bridge not a valid PKCS7 type.");
        return;
    }

    if (certs != NULL)
    {
	int numcerts = sk_X509_num(certs);
	for (int i = 0; i<numcerts; i++)
	{
            shared_ptr<WvX509> x(new WvX509(X509_dup(sk_X509_value(certs, i))));
            certmap.insert(CertPair(x->get_ski().cstr(), x));
        }
    }
    else 
    {
        log(WvLog::Warning, "No valid certificates in PKCS7 blob.");
    }
}


shared_ptr<WvX509> WvX509Store::get(WvStringParm ski)
{
    pair<CertMap::iterator, CertMap::iterator> iterpair = 
    certmap.equal_range(ski.cstr());

    for (CertMap::iterator i = iterpair.first; i != iterpair.second; i++)
        return((*i).second);
    
    return boost::shared_ptr<WvX509>();
}

void WvX509Store::get(WvStringParm ski, WvX509List &certlist)
{
    pair<CertMap::iterator, CertMap::iterator> iterpair = 
    certmap.equal_range(ski.cstr());

    for (CertMap::iterator i = iterpair.first; i != iterpair.second; i++)
        certlist.push_back((*i).second);
}


bool WvX509Store::exists(WvX509 * cert)
{
    shared_ptr<WvX509> cacert = get(cert->get_ski());
    if (!cacert)
    {
        log("No certificate corresponding to %s (with ski: %s) in store.\n", 
            cert->get_subject(), cert->get_ski());
        return false;
    }

    // otherwise check that the cert is signed
    if (!cert->validate(cacert.get()))
    {
        log("Certificate with subject %s does not validate!\n", 
            cert->get_subject());
        return false;
    }

    log("Certificate %s seems to exist in store (as %s).\n", cert->get_subject(),
        cacert->get_subject());
    return true;
}


bool WvX509Store::exists(WvStringParm ski)
{
    return (get(ski));
}


void WvX509Store::get_cross_certs(shared_ptr<WvX509> &cert,
                                  vector< shared_ptr<WvX509> > &certlist)
{
    for (CertMap::iterator i = certmap.begin();
         i != certmap.end(); i++)
    {
        log("Checking %s (ski:%s aki:%s issuer:%s) against %s (ski:%s aki:%s)\n", 
            (*i).second->get_subject(), (*i).second->get_issuer(), (*i).second->get_ski(), (*i).second->get_aki(),
            cert->get_subject(), cert->get_ski(), cert->get_aki());
        if ((*i).second->get_subject() == cert->get_subject() &&
            (*i).second->get_aki() != cert->get_aki() &&
            (*i).second->get_aki() != (*i).second->get_ski())
        {
            log("%s matches.\n", (*i).second->get_subject());
           certlist.push_back((*i).second);
        }
    }
}

int WvX509Store::count()
{
    return certmap.size();
}
