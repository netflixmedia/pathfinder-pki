/*
 * pathclient.cc
 *
 * Copyright (C) 2007 Carillon Information Security Inc.
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
#include "wvdbuslistener.h"
#include "wvx509policytree.h"

static bool done = false;

static void validate_cb(bool valid, WvString reason, WvError err)
{
    if (err.isok())
    {
        wvcon->print("Certificate is %svalid.\n", valid ? "" : "NOT ");
        if (!valid)
            wvcon->print("Reason for failure: %s.\n", reason);
    }
    else
        wverr->print("There was an error attempting to validate (%s).\n",
                     err.errstr());
    done = true;
}


int main(int argc, char *argv[])
{
    wvcrash_setup(argv[0]);
    
    WvStringList remaining_args;
    WvString certtype = "pem";
    bool session_bus = false;
    bool initial_explicit_policy = false;
    bool initial_policy_mapping_inhibit = false;

    WvArgs args;
    args.add_required_arg("CERTIFICATE");
    args.add_option('t', "type", "Certificate type: der or pem (default: pem)", 
                    "type", certtype);
    args.add_set_bool_option('\0', "session", "Listen on the session "
                             "bus (instead of the system bus)", 
                             session_bus);    
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
    
    WvDBusConn *conn = NULL;
    if (session_bus)
        conn = new WvDBusConn(DBUS_BUS_SESSION);
    else
        conn = new WvDBusConn(DBUS_BUS_SYSTEM);

    WvDBusMsg msg("ca.carillon.pathfinder", "/ca/carillon/pathfinder", 
                  "ca.carillon.pathfinder", "validate");
    msg.append(x509.encode(WvX509::CertHex));
    msg.append(WvString(ANY_POLICY_OID));
    msg.append(initial_explicit_policy);
    msg.append(initial_policy_mapping_inhibit);

    // expect a reply with a bool and a single string as an argument
    WvDBusListener<bool,WvString> reply("/ca/carillon/pathfinder/validate", validate_cb);
    conn->send(msg, &reply, false);

    WvIStreamList::globallist.append(conn, true, "wvdbus conn");
    
    while (WvIStreamList::globallist.isok() && !done)
        WvIStreamList::globallist.runonce();
    
    return 0;
}
