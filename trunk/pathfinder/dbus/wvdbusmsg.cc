/* -*- Mode: C++ -*-
 * Worldvisions Weaver Software:
 *   Copyright (C) 2004-2006 Net Integration Technologies, Inc.
 * 
 * Pathfinder Software:
 *   Copyright (C) 2007, Carillon Information Security Inc.
 *
 * This library is licensed under the LGPL, please read LICENSE for details.
 *
 */ 
#include "wvdbusmsg.h"


WvDBusMsg::WvDBusMsg(WvStringParm busname, WvStringParm objectname, 
                     WvStringParm interface, WvStringParm method)
{
    msg = dbus_message_new_method_call(busname, objectname, interface, method);
    dbus_message_iter_init_append(msg, &iter);
}


void WvDBusMsg::append(WvStringParm s1)
{
    assert(msg);
    const char *tmp;
    if (!s1.isnull())
    {
	tmp = s1.cstr();
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &tmp);
    }
}


void WvDBusMsg::append(bool b)
{
    assert(msg);
    int i = b;
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_BOOLEAN, &i);
}


void WvDBusMsg::append(char c)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_BYTE, &c);
}


void WvDBusMsg::append(int16_t i)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT16, &i);
}


void WvDBusMsg::append(uint16_t i)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT16, &i);
}


void WvDBusMsg::append(int32_t i)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &i);
}


void WvDBusMsg::append(uint32_t i)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &i);
}


void WvDBusMsg::append(double d)
{
    assert(msg);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_DOUBLE, &d);
}


WvDBusReplyMsg::WvDBusReplyMsg(DBusMessage *_msg) 
{
    assert(_msg);
    msg = dbus_message_new_method_return(_msg);
    printf("Iterator initialized for appending!\n");
    dbus_message_iter_init_append(msg, &iter);
}


WvDBusSignal::WvDBusSignal(WvStringParm objectname, WvStringParm interface,
                           WvStringParm name)
{
    msg = dbus_message_new_signal(objectname, interface, name);
    dbus_message_iter_init_append(msg, &iter);
}
