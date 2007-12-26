/*
 * pathverify.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <uniconfroot.h>
#include <wvargs.h>
#include <wvcrash.h>
#include <wvlogrcv.h>
#include <wvistreamlist.h>

#include "pathvalidator.h"

using namespace boost;

#define DEFAULT_CONFIG_MONIKER "ini:/etc/pathfinderd.ini"
#define DEFAULT_POLICY "2.5.29.32.0"


static WvLog::LogLevel log_level = WvLog::Info;
static bool done = false;


static bool dec_log_level(void *)
{
    if ((int)log_level > (int)WvLog::Critical)
        log_level = (WvLog::LogLevel)((int)log_level - 1);
    return true;
}


static bool inc_log_level(void *)
{
    if ((int)log_level < (int)WvLog::Debug5)
        log_level = (WvLog::LogLevel)((int)log_level + 1);
    return true;
}


static void path_validated_cb(boost::shared_ptr<WvX509> &cert, bool valid, WvError err,
                              void *userdata)
{
    done = true;

    if (err.geterr())
    {
        wvcon->print("Error while validating path (%s)\n", err.errstr());
        return;
    }

    wvcon->print("Path validated. Result: %s.\n", valid ? "valid" : "invalid");
}

int main(int argc, char *argv[])
{
    wvcrash_setup(argv[0]);
    
    WvStringList remaining_args;
    WvString certtype("pem");
    WvString cfgmoniker(DEFAULT_CONFIG_MONIKER);
    WvString initial_policy_set_tcl(DEFAULT_POLICY);
    bool crl_check = true;

    WvArgs args;
    args.add_required_arg("CERTIFICATE");
    args.add_option('t', "type", "Certificate type: der or pem (default: pem)", 
                    "TYPE", certtype);
    args.add_option('p', "policy", "Initial policy set to use for validation, "
                    "in tcl-encoded form (default: " DEFAULT_POLICY ")",
                    "POLICY", initial_policy_set_tcl);
    args.add_option('c', "config", WvString("Config moniker (default: %s)",
                                            DEFAULT_CONFIG_MONIKER),
                    "ini:filename.ini", cfgmoniker);
    args.add_option('q', "quiet",
            "Decrease log level (can be used multiple times)",
            WvArgs::NoArgCallback(&dec_log_level));
    args.add_option('v', "verbose",
            "Increase log level (can be used multiple times)",
            WvArgs::NoArgCallback(&inc_log_level));
    args.add_reset_bool_option('\0', "skip-crl-check", "Skips any CRL checking.",
                               crl_check);

    if (!args.process(argc, argv, &remaining_args))
    {
        args.print_help(argc, argv);
        return 1;
    }

    WvLogConsole console_log(1, log_level);

    UniConfRoot cfg(cfgmoniker);

    WvString certname = remaining_args.popstr();

    shared_ptr<WvX509Store> trusted_store(new WvX509Store);
    {
        UniConf::Iter i(cfg["trusted directories"]);
        for (i.rewind(); i.next();)
            trusted_store->load(i->getme());        
    }
    shared_ptr<WvX509Store> intermediate_store(new WvX509Store);
    {
        UniConf::Iter i(cfg["bridges"]);
        for (i.rewind(); i.next();)
            intermediate_store->add_pkcs7(i->getme());
    }

    shared_ptr<WvX509> x509(new WvX509);
    if (certtype == "der")
        x509->decode(WvX509::CertFileDER, certname);   
    else if (certtype == "pem")
        x509->decode(WvX509::CertFilePEM, certname);
    else
    {
        wverr->print("Invalid certificate type '%s'\n", certtype);
        return -1;
    }

    if (!x509->isok())
    {
        wverr->print("Certificate is NOT ok. Not doing path validation.\n");
        return -1;
    }

    PathValidator p(x509, initial_policy_set_tcl, crl_check ? 0 : WVX509_SKIP_CRL_CHECK, 
                    trusted_store, intermediate_store,
                    cfg, path_validated_cb, NULL);
    p.validate();

    while (!done && WvIStreamList::globallist.isok())
        WvIStreamList::globallist.runonce();
}

