/*
 * pathclient.cc
 *
 * Copyright (C) 2007-2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <wvargs.h>
#include <wvcrash.h>
#include <wvistreamlist.h>
#include <wvstream.h>
#include <wvx509.h>

#include "wvdbusconn.h"
#include "wvdbusmsg.h"
#include "wvx509policytree.h"

static bool done = false;

static bool reply(WvDBusMsg &msg)
{
    wvout->print("got reply: %s\n", msg.get_argstr());

    done = true;
    
    return true;
}


int main(int argc, char *argv[])
{
    wvcrash_setup(argv[0]);
    
    WvStringList remaining_args;
    WvString certtype = "pem";
    WvString moniker("dbus:system");
    bool initial_explicit_policy = false;
    bool initial_policy_mapping_inhibit = false;

    WvArgs args;
    args.add_required_arg("CERTIFICATE");
    args.add_option('m', "moniker", "Specify the dbus moniker to use "
                    "(default: dbus:system)", "MONIKER", moniker);
    args.add_option('t', "type", "Certificate type: der or pem (default: pem)", 
                    "type", certtype);
    args.add_set_bool_option('e', "initial-explicit-policy", "Set initial "
                             "explicit policy when validating", 
                             initial_explicit_policy);    
    args.add_set_bool_option('p', "initial-policy-mapping-inhibit", "Inhibit "
                             "policy mapping when validating", 
                             initial_policy_mapping_inhibit);    
    
    if (!args.process(argc, argv, &remaining_args))
    {
        args.print_help(argc, argv);
        return 1;
    }

    WvString certname = remaining_args.popstr();

    WvX509 x509;
    if (certtype == "der")
        x509.decode(WvX509::CertFileDER, certname);   
    else if (certtype == "pem")
        x509.decode(WvX509::CertFilePEM, certname);
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
    
    WvDBusConn conn(moniker);
    WvIStreamList::globallist.append(&conn, false, "wvdbus conn");

    WvDBusMsg msg("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                  "ca.carillon.pathfinder", "validate");
    msg.append(x509.encode(WvX509::CertHex));
    msg.append(WvString(ANY_POLICY_OID));
    msg.append(initial_explicit_policy);
    msg.append(initial_policy_mapping_inhibit);

    wvout->print("Message sent to daemon: busname: ca.carillon.pathfinder\n");
    wvout->print("object: /ca/carillon/pathfinder method: validate\n");
    wvout->print("parameter1: %s\n", x509.encode(WvX509::CertHex));
    wvout->print("parameter2: %s\n", WvString(ANY_POLICY_OID));
    
    conn.send(msg, &reply);

    while (WvIStreamList::globallist.isok() && !done)
        WvIStreamList::globallist.runonce();
    
    return 0;
}
