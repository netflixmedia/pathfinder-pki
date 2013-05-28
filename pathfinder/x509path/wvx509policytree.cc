/* -*- Mode: C++ -*-
 * X.509 certificate path management classes.
 *
 * Copyright (C) 2007-2012 Carillon Information Security Inc.
 * 
 * This library is covered by the LGPL v2.1 or later, please read LICENSE for details.
 */ 

#include "wvx509policytree.h"

using namespace boost;


WvX509PolicyNode::WvX509PolicyNode(WvStringParm _valid_policy) :
    log("X509 Policy Node", WvLog::Debug5)
{
    valid_policy = _valid_policy;
    expected_policy_set.append(_valid_policy);
}


WvX509PolicyNode::WvX509PolicyNode() :
    log("X509 Policy Node", WvLog::Debug5)
{
    valid_policy = ANY_POLICY_OID;
    expected_policy_set.append(valid_policy);
}


void WvX509PolicyNode::append_child(WvStringParm oid)
{
    log("Appending child with OID %s to node with OID %s\n", 
        oid, valid_policy);
    shared_ptr<WvX509PolicyNode> node(new WvX509PolicyNode(oid));
    children.push_back(node);
}


WvX509PolicyTree::WvX509PolicyTree() :
    root(new WvX509PolicyNode),
    log("X509 Policy Tree", WvLog::Debug5)
{
}


bool WvX509PolicyTree::isnull()
{
    if (!root)
        return true;

    return false;
}

void WvX509PolicyTree::remove(WvStringParm oid, int level)
{
    if (isnull())
        return;

    if (remove_internal(oid, root, level))
    {
        shared_ptr<WvX509PolicyNode> nullnode;
        root = nullnode;
    }        
}


bool WvX509PolicyTree::remove_internal(WvStringParm oid,
                                       shared_ptr<WvX509PolicyNode> &node, 
                                       int level)
{
    if (level == 0)
    {
        if (node->valid_policy == oid)
            return true;
    }

    for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
    {
        if (remove_internal(oid, (*i), (level - 1)))
        {
            node->children.erase(i);
            return false;
        }            
    }

    return false;
}


bool WvX509PolicyTree::remove(shared_ptr<WvX509PolicyNode> &curnode, 
                              shared_ptr<WvX509PolicyNode> &node_to_remove)
{
    // base case: root node should be removed (this should never happen,
    // presently)
    assert(root != node_to_remove);

    // other case: a child of the root node should be removed... as we call 
    // this function recursively
    for (WvX509PolicyNode::List::iterator i = curnode->children.begin(); 
         i != curnode->children.end(); i++)
    {
        if ((*i) == node_to_remove)
        {
            curnode->children.erase(i);
            return true;
        }

        if (remove((*i), node_to_remove))
            return true;
    }

    return false;
}


void WvX509PolicyTree::intersection(WvStringList &initial_policy_set, 
                                    int level)
{
    if (isnull())
        return;

    // (1) Calculate the valid policy node set
    WvX509PolicyNode::List valid_policy_node_set;
    get_valid_policy_node_set(root, valid_policy_node_set);
    // (2) remove any nodes in the valid_policy_node_set which are not
    // in the initial policy set and are not anyPolicy
    WvX509PolicyNode::List::iterator end = valid_policy_node_set.end();
    WvX509PolicyNode::List::iterator i = valid_policy_node_set.begin(); 
    while (i != end)
    {
        bool match = false;
        WvStringList::Iter j(initial_policy_set);
        for (j.rewind(); j.next();)
        {
            if (j() == (*i)->valid_policy)
            {
                match = true;
                break;
            }
        }
        if (!match && (*i)->valid_policy != ANY_POLICY_OID)
        {
            log("Removing node with valid policy %s because it's not in "
                "the initial policy set.\n", (*i)->valid_policy);
            remove(root, (*i));
            valid_policy_node_set.erase(i);
            i = valid_policy_node_set.begin(); 
            end = valid_policy_node_set.end();
        }
        else 
            i++;
    }
    
    // (3) FIXME: Implement the algorithm for replacing leaf nodes with
    // anyPolicy as valid_policy
    
    // (4) prune
    prune(level);
}


void WvX509PolicyTree::get_valid_policy_node_set(
    shared_ptr<WvX509PolicyNode> &node, 
    WvX509PolicyNode::List &valid_policy_node_set)
{
    if (node->valid_policy == ANY_POLICY_OID)
    {
        for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
            valid_policy_node_set.push_back((*i));
    
    }
    
    for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
        get_valid_policy_node_set((*i), valid_policy_node_set);
    
}


void WvX509PolicyTree::prune(int level)
{
    if (isnull())
        return;

    // prune the root if it has no children
    if (!prune_internal(root, level))
    {
        log("Root has no children after pruning. Removing.\n");
        shared_ptr<WvX509PolicyNode> nullnode;
        root = nullnode;
    }
}


bool WvX509PolicyTree::prune_internal(shared_ptr<WvX509PolicyNode> &node,
                                      int level)
{
    log("prune internal. level: %s\n", level);
    // expected level: ok, any parent node of this node should be kept
    if (level == 0)
        return true;

    bool one_valid_child = false;
    WvX509PolicyNode::List::iterator end = node->children.end();
    WvX509PolicyNode::List::iterator i = node->children.begin(); 
    while (i != end)
    {
        if (!prune_internal((*i), (level - 1)))
        {
            log("Removing node with valid policy %s.\n", (*i)->valid_policy);
            node->children.erase(i);
            i = node->children.begin();
            end = node->children.end();
        }
        else
        {
            one_valid_child = true;
            log("Not removing node %s because it has children.\n", (*i)->valid_policy);
            i++;
        }
    }

    return one_valid_child;
}


bool WvX509PolicyTree::link(WvStringParm oid, int level, bool any_policy)
{
    return link_internal(oid, root, level, any_policy);
}


bool WvX509PolicyTree::link_internal(WvStringParm oid, 
                                     shared_ptr<WvX509PolicyNode> &node, 
                                     int level, bool any_policy)
{
    if (!node)
        return false;

    if (level == 0)
    {
        if (node->valid_policy == ANY_POLICY_OID)
        {
            if (any_policy)
            {
                node->append_child(oid);
                return true;
            }
        }
        else 
        {
            WvStringList::Iter i(node->expected_policy_set);
            for (i.rewind(); i.next();)
            {
                if (i() == oid)
                {
                    node->append_child(oid);
                    return true;
                }
            }
        }

        return false;
    }

    bool found_link = false;
    for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
    {
        found_link |= link_internal(oid, (*i), (level - 1), any_policy);
    }

    return found_link;
}


void WvX509PolicyTree::extend_any_policy(int level)
{
    extend_any_policy_internal(root, level);
}


void WvX509PolicyTree::extend_any_policy_internal(
    shared_ptr<WvX509PolicyNode> &node, int level)
{
    if (!node)
        return;

    if (level == 0)
    {
        log("Checking for extension at node %s.\n", node->valid_policy);
        WvStringList::Iter i(node->expected_policy_set);
        for (i.rewind(); i.next();)
        {
            bool node_exists = false;
            for (WvX509PolicyNode::List::iterator j = node->children.begin(); 
                 j != node->children.end(); j++)
            {
                if ((*j)->valid_policy == i())
                {
                    log("Node exists. Not extending.\n");
                    node_exists = true;
                    break;
                }
            }

            log("Trying to extend via anyPolicy and no child node with "
                "expected OID %s. Extending.\n", i());
            if (!node_exists)
                node->append_child(i());
        }

        return;
    }

    for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
    {
        extend_any_policy_internal((*i), (level - 1));
    }
}


void WvX509PolicyTree::append_mapping(WvX509::PolicyMapList &list, 
                                      int level)
{
    append_mapping_internal(list, root, level);
}


void WvX509PolicyTree::append_mapping_internal(WvX509::PolicyMapList &list,  
                                               shared_ptr<WvX509PolicyNode> &node,
                                               int level)
{
    if (!node)
        return;

    if (level == 0)
    {
        WvX509::PolicyMapList::Iter i(list);
        for (i.rewind(); i.next();)
        {
            if (node->valid_policy == i().issuer_domain)
            {
                // FIXME:  this doesn't seem right -- we're setting the
                // expected policy set to ALL subject domain OIDs?  It
                // should be only subject domain OIDs that are mapped to
                // the given issuer domain OID.

                // ok, we have at least one mapping here
                // we replace the expected policy set with the mappings 
                // (6.1.4 b in RFC3280)                
                node->expected_policy_set.zap();
                log("Replacing expected policy set with mappings.\n");
                for (i.rewind(); i.next();)
                {
                    node->expected_policy_set.append(i().subject_domain);
                    log("Appending %s to expected policy set.\n", 
                        i().subject_domain);
                }
                return;                
            }
        }
        return;
    }    

    for (WvX509PolicyNode::List::iterator i = node->children.begin(); 
         i != node->children.end(); i++)
    {
        append_mapping_internal(list, (*i), (level - 1));
    }

}
