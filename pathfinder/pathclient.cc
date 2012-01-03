/*
 * pathclient.cc
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <wvargs.h>
#include <wvcrash.h>
#include <wvistreamlist.h>
#include <wvlogrcv.h>
#include <wvstream.h>
#include <wvdbusconn.h>
#include <wvx509.h>

#include "wvx509policytree.h" // for ANY_POLICY_OID
#include "util.h"

static WvLog::LogLevel log_level = WvLog::Info;
static bool done = false;

static bool reply(WvDBusMsg &msg)
{
    if (msg.iserror())
    {
        wvout->print("Error response (%s) to validation request.\n", 
                     msg.get_error());
        done = true;
        return true;
    }

    WvDBusMsg::Iter args(msg);
    bool ok = args.getnext();
    WvString errstr = args.getnext();

    if (ok)
        wvout->print("Pathfinder daemon says certificate is ok.\n");
    else 
    {
        wvout->print("Certificate is NOT ok. Error: %s.\n", errstr);
    }

    done = true;
    
    return true;
}


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


int main(int argc, char *argv[])
{
    wvcrash_setup(argv[0]);
    
    WvStringList remaining_args;
    WvString certtype;
    WvString moniker("dbus:system");
    bool initial_explicit_policy = false;
    bool initial_policy_mapping_inhibit = false;

    WvArgs args;
    args.add_required_arg("CERTIFICATE");
    args.add_option('m', "moniker", "Specify the dbus moniker to use "
                    "(default: dbus:system)", "MONIKER", moniker);
    args.add_option('t', "type", "Certificate type: der or pem "
                    "(default: autodetect)", 
                    "type", certtype);
    args.add_set_bool_option('e', "initial-explicit-policy", "Set initial "
                             "explicit policy when validating", 
                             initial_explicit_policy);    
    args.add_set_bool_option('p', "initial-policy-mapping-inhibit", "Inhibit "
                             "policy mapping when validating", 
                             initial_policy_mapping_inhibit);    
    args.add_option('q', "quiet",
            "Decrease log level (can be used multiple times)",
            WvArgs::NoArgCallback(&dec_log_level));
    args.add_option('v', "verbose",
            "Increase log level (can be used multiple times)",
            WvArgs::NoArgCallback(&inc_log_level));
    
    if (!args.process(argc, argv, &remaining_args))
    {
        args.print_help(argc, argv);
        return 1;
    }

    WvLogConsole console_log(1, log_level);

    WvString certname = remaining_args.popstr();

    WvX509 x509;
    if (certtype == "der")
        x509.decode(WvX509::CertFileDER, certname);   
    else if (certtype == "pem")
        x509.decode(WvX509::CertFilePEM, certname);
    else if (!certtype)
        x509.decode(guess_encoding(certname), certname);
    else
    {
        wverr->print("Invalid certificate type '%s'\n", certtype);
        return -1;
    }

    if (!x509.isok())
    {
        wverr->print("Certificate is NOT ok. Not doing path validation.\n");
        return -1;
    }

    // HACK: dbus:system doesn't correspond to anything useful most of the
    // time, use a hardcoded value instead that should be valid for most
    // systems
    if (moniker == "dbus:system")
        moniker = "unix:/var/run/dbus/system_bus_socket";
    WvDBusConn conn(moniker);
    WvIStreamList::globallist.append(&conn, false, "wvdbus conn");

    WvDBusMsg msg("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                  "ca.carillon.pathfinder", "validate");
    msg.append(x509.encode(WvX509::CertHex));
    msg.append(WvString(ANY_POLICY_OID));
    msg.append(initial_explicit_policy);
    msg.append(initial_policy_mapping_inhibit);

#if 0
    wvout->print("Message sent to daemon: busname: ca.carillon.pathfinder\n");
    wvout->print("object: /ca/carillon/pathfinder method: validate\n");
    wvout->print("parameter1: %s\n", x509.encode(WvX509::CertHex));
    wvout->print("parameter2: %s\n", WvString(ANY_POLICY_OID));
#endif
    
    conn.send(msg, &reply);

    while (WvIStreamList::globallist.isok() && !done)
        WvIStreamList::globallist.runonce();
    
    return 0;
}
