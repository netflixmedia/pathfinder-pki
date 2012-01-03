/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */ 

#ifndef __WVX509POLICYTREE_H
#define __WVX509POLICYTREE_H
#include <boost/shared_ptr.hpp>
#include <vector>
#include <wvlog.h>
#include <wvstring.h>
#include <wvx509.h>


#define ANY_POLICY_OID "2.5.29.32.0"


class WvX509PolicyNode
{
  public:
    WvX509PolicyNode(WvStringParm _valid_policy);
    WvX509PolicyNode();
    void append_child(WvStringParm oid);
    //std::vector<int> qualifier_set;
    //bool criticality_indicator;
    WvString valid_policy;
    WvStringList expected_policy_set;
    typedef std::vector<boost::shared_ptr<WvX509PolicyNode> > List;
    List children;
    WvLog log;
};


class WvX509PolicyTree
{
  public:
    WvX509PolicyTree();
    bool contains_any_policy(int level);
    bool remove(boost::shared_ptr<WvX509PolicyNode> &curnode, 
                boost::shared_ptr<WvX509PolicyNode> &node_to_remove);
    void intersection(WvStringList &initial_policy_set, int level);
    void get_valid_policy_node_set(
        boost::shared_ptr<WvX509PolicyNode> &node, 
        WvX509PolicyNode::List &valid_policy_node_set);
    void prune(int level);    
    bool link(WvStringParm oid, int level, bool any_policy);
    void remove(WvStringParm oid, int level);
    void extend_any_policy(int level);
    void append_mapping(WvX509::PolicyMapList &list, 
                        int level);
    bool isnull();

  private:
    bool prune_internal(boost::shared_ptr<WvX509PolicyNode> &node, int level);
    bool link_internal(WvStringParm oid, 
                       boost::shared_ptr<WvX509PolicyNode> &node, int level,
                       bool any_policy);
    bool remove_internal(WvStringParm oid, 
                         boost::shared_ptr<WvX509PolicyNode> &node, int level);
    void extend_any_policy_internal(boost::shared_ptr<WvX509PolicyNode> &node, 
                                    int level);
    void append_mapping_internal(WvX509::PolicyMapList &list,  
                                 boost::shared_ptr<WvX509PolicyNode> &node,
                                 int level);

    boost::shared_ptr<WvX509PolicyNode> root;
    WvLog log;
};

#endif // __WVX509POLICYTREE_H
