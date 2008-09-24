/*
 * pathserver.h
 *
 * Copyright (C) 2007-2008 Carillon Information Security Inc.
 *
 * This program and accompanying library is covered by the LGPL v2.1 or later, 
 * please read LICENSE for details.
 */

#include <map>
#include <uniconf.h>
#include <wvdbusconn.h>

#include "pathvalidator.h"
#include "wvx509store.h"


class PathServer
{
  public:
    PathServer(boost::shared_ptr<WvX509Store> _trusted_store,
               boost::shared_ptr<WvX509Store> _intermediate_store,
               boost::shared_ptr<WvCRLStore> _crlstore,
               UniConf &cfg);
    bool incoming(WvDBusConn *conn, WvDBusMsg &msg);

  private:
    void path_validated_cb(boost::shared_ptr<WvX509> &cert, bool valid, 
                           WvError err, WvDBusConn *conn, WvDBusMsg *reply);

    typedef std::map<WvDBusMsg *, boost::shared_ptr<PathValidator> > ValidatorMap;
    ValidatorMap validatormap;

    boost::shared_ptr<WvX509Store> trusted_store;
    boost::shared_ptr<WvX509Store> intermediate_store;
    boost::shared_ptr<WvCRLStore> crlstore;
    UniConf cfg;

    WvLog log;

};
