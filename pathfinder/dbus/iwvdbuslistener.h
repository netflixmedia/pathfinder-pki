/* -*- Mode: C++ -*-
 * Worldvisions Weaver Software:
 *   Copyright (C) 2005 Net Integration Technologies, Inc.
 *
 * Pathfinder Software:
 *   Copyright (C) 2007, Carillon Information Security Inc.
 *
 * This library is licensed under the LGPL, please read LICENSE for details.
 * 
 */ 
#ifndef __IWVDBUSLISTENER_H
#define __IWVDBUSLISTENER_H
#include "wvcallback.h"
#include "wvstring.h"

#include <assert.h>
#include <dbus/dbus.h>

class WvDBusConn;

class IWvDBusListener
{
public:
    IWvDBusListener(WvStringParm _member) { member = _member; }
    virtual ~IWvDBusListener() {}
    virtual void dispatch(DBusMessage *_msg) = 0;

    WvString member;
};

#endif // __IWVDBUSLISTENER_H
