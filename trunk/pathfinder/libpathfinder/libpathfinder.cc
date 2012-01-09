/*
 * libpathfinder.cc
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 *
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */
#include <dbus/dbus.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {

int pathfinder_app_dbus_verify(const char *appname,
                               const char *certhex, const char *policy, 
                               const int initial_explicit_policy, 
                               const int initial_policy_mapping_inhibit,
                               char **errmsg)
{
    *errmsg = NULL; // sometimes we can't return a proper error
    if (!certhex || !policy)
    {
        *errmsg = strdup("Invalid arguments to verification call");
        return 0;
    }

    DBusConnection* conn = NULL;
    DBusError err;  
    int ret;
    
    dbus_error_init(&err);
    
    DBusBusType bustype = DBUS_BUS_SYSTEM;
    if (getenv("PATHFINDER_USE_SESSION_BUS"))
        bustype = DBUS_BUS_SESSION;

    conn = dbus_bus_get(bustype, &err);
    if (!conn || dbus_error_is_set(&err))
    {
        dbus_error_free(&err);
        dbus_connection_unref(conn);
        *errmsg = strdup("Can't get connection to bus");
        return 0;
    }

    DBusMessage* msg = NULL;
    DBusPendingCall* pending;
    
    msg = dbus_message_new_method_call("ca.carillon.pathfinder",
                                       "/ca/carillon/pathfinder",
                                       "ca.carillon.pathfinder",
                                       "validate");
    if (!msg)
    {
        dbus_connection_unref(conn);
        return 0;
    }

    if (appname && appname[0])
    {
        if (!dbus_message_append_args(msg,
                    DBUS_TYPE_STRING, &certhex, 
                    DBUS_TYPE_STRING, &policy,
                    DBUS_TYPE_BOOLEAN, &initial_explicit_policy,
                    DBUS_TYPE_BOOLEAN, &initial_policy_mapping_inhibit,
                    DBUS_TYPE_STRING, &appname,
                    DBUS_TYPE_INVALID))
        {
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return 0;
        }
    }
    else
    {
        if (!dbus_message_append_args(msg,
                    DBUS_TYPE_STRING, &certhex, 
                    DBUS_TYPE_STRING, &policy,
                    DBUS_TYPE_BOOLEAN, &initial_explicit_policy,
                    DBUS_TYPE_BOOLEAN, &initial_policy_mapping_inhibit,
                    DBUS_TYPE_INVALID))
        {
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return 0;
        }
    }


    if (!dbus_connection_send_with_reply(conn, msg, &pending, -1) || 
        !pending)
    {
        dbus_message_unref(msg);
        dbus_connection_unref(conn);
        return 0;
    }

    dbus_connection_flush(conn);
    dbus_message_unref(msg);

    dbus_pending_call_block(pending);
    msg = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);

    if (!msg)
    {
        dbus_connection_unref(conn);
        return 0;
    }

    if (dbus_message_get_type(msg) == DBUS_MESSAGE_TYPE_ERROR)
    {
        *errmsg = strdup("Could not contact Pathfinder daemon");
        dbus_message_unref(msg);
        dbus_connection_unref(conn);
        return 0;
    }

    DBusMessageIter args;
    dbus_bool_t validated = 0;
    if (!dbus_message_iter_init(msg, &args))
    {
        dbus_message_unref(msg);
        dbus_connection_unref(conn);
        return 0;
    }

    if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN)
    {
        *errmsg = strdup("Invalid argument in Pathfinder reply");
        dbus_message_unref(msg);
        dbus_connection_unref(conn);
        return 0;
    }

    dbus_message_iter_get_basic(&args, &validated);

    if (!validated)
    {
        dbus_message_iter_next(&args);

        char *s;       
        if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)
        {
            *errmsg = strdup("Invalid argument in Pathfinder reply");
            dbus_message_unref(msg);
            dbus_connection_unref(conn);
            return 0;
        }

        dbus_message_iter_get_basic(&args, &s);
        *errmsg = strdup(s);
    }    

    dbus_message_unref(msg);
    dbus_connection_unref(conn);

    return validated;
}

int pathfinder_dbus_verify(const char *certhex, const char *policy, 
                           const int initial_explicit_policy, 
                           const int initial_policy_mapping_inhibit,
                           char **errmsg)
{
    return pathfinder_app_dbus_verify(NULL, certhex, policy,
                                      initial_explicit_policy,
                                      initial_policy_mapping_inhibit,
                                      errmsg);
}

}
