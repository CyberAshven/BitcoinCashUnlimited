// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_DAG_H
#define BITCOIN_TAILSTORM_DAG_H

// tailstorm file includes
#include "subblock/subblock.h"

// other bitcoin includes
#include "sync.h"

#include <deque>
#include <queue>
#include <set>

// CTreeNode has a header only implementation
class CTreeNode
{
public:
    uint256 hash; // the weakblock hash that is this node
    uint16_t dag_id;
    unsigned int height;

    CSubBlock subblock;

    CTreeNode* ancestor; // should point to the node of the parentHash
    std::set<CTreeNode*> vDescendents; // points to the nodes of the children

private:
    CTreeNode(){} // disable default constructor

public:
    CTreeNode(CSubBlock _subblock)
    {
        hash = _subblock.GetHash();
        subblock = _subblock;
        height = 1;
    }

    friend bool operator<(const CTreeNode &a, const CTreeNode &b)
    {
        return a.hash < b.hash;
    }

    void AddAncestor(CTreeNode* _ancestor)
    {
        ancestor = _ancestor;
    }

    void AddDescendant(CTreeNode* _descendent)
    {
        vDescendents.emplace(_descendent);
    }

    // there is nothing below it
    bool IsBase()
    {
        return (ancestor == nullptr);
    }

    // there is nothing above it
    bool IsTip()
    {
        return vDescendents.empty();
    }

    bool IsValid()
    {
        return (subblock.IsNull() == false);
    }
};

class CTailstormTree
{
    friend class CTailstormGrove;
protected:
    // TODO rootHash should be const
    uint256 rootHash;
    // id should be 0
    uint16_t id;
    // pointers point to the nodes for this dag, a pointer to the same node is
    // also available in mapAllNodes at the forest level
    std::deque<CTreeNode*> _dag;
    // output spent, the tx hash it was spent in
    std::map<COutPoint, uint256> spent_outputs;

private:
    CTailstormTree(){} // disable default constructor

protected:
    bool CheckForCompatibility(CTreeNode* newNode);

public:
    CTailstormTree(CTreeNode* first_node)
    {
        id = first_node->dag_id;
        rootHash = first_node->subblock.hashPrevBlock;
        Insert(first_node);
    }
    bool Insert(CTreeNode* new_node);
};

// this class can not have any public data members, all datamembers are
// protected by cs_dagset
class CTailstormGrove
{
    friend class CTailstormForest;
protected:
    CSharedCriticalSection cs_grove;
    // TODO will need a shadow tree(s) to keep track of subblock heights if
    // a conflict arises so we can mine of best common to not lose entire subblock
    // rewards
    CTailstormTree _tree;
    // key is subblock hash for the node in value
    std::map<uint256, CTreeNode*> mapAllGroveNodes;
    std::map<uint256, CTreeNode*> mapUnusedNodes;

protected:
    void _CreateNewTree(CTreeNode* newNode);
    bool _InsertIntoTree(CTreeNode* newNode);
    void _CheckOrphans(const uint256 &hash);

    CTailstormGrove()
    {
        Clear();
    }

    void Clear();

    bool Insert(CTreeNode* newNode);
    bool GetBestDag(std::set<CTreeNode> &dag);
    bool GetBestTipHash(uint256 &hash);
};

class CTailstormForest
{
    friend class CTailstormGrove;
protected:
    CSharedCriticalSection cs_forest;
    // key is subblock hash for the node in value
    std::map<uint256, CTreeNode*> mapAllNodes;
    // key is prevBlockHash of the nodes in the Grove
    std::map<uint256, CTailstormGrove*> vGroves;

public:
    CTailstormForest()
    {
        WRITELOCK(cs_forest);
        vGroves.clear();
        mapAllNodes.clear();
    }

    ~CTailstormForest()
    {
        Clear();
    }

    void Clear()
    {
        WRITELOCK(cs_forest);
        for (auto &grove : vGroves)
        {
            // clearing a grove removes those nodes from mapAllNodes
            grove.second->Clear();
            delete grove.second;
        }
        mapAllNodes.clear();
    }

    void ClearGrove(const uint256& hash)
    {
        WRITELOCK(cs_forest);
        auto iter = vGroves.find(hash);
        if (iter != vGroves.end())
        {
            iter->second->Clear();
            delete iter->second;
            vGroves.erase(iter);
        }
    }

    size_t Size()
    {
        READLOCK(cs_forest);
        return mapAllNodes.size();
    }

    // Insert should only be called by ProcessNewSubBlock except for in tests
    bool Insert(const CSubBlock &sub_block)
    {
        WRITELOCK(cs_forest);
        const uint256 sub_block_hash = sub_block.GetHash();
        CTreeNode* newNode = nullptr;
        auto iter = mapAllNodes.find(sub_block_hash);
        if (iter != mapAllNodes.end())
        {
            // we already have this subblock in a da
            newNode = iter->second;
        }
        else
        {
            // Create new
            newNode = new CTreeNode(sub_block);
            // this emplace will always succeed since we already checked for the hash above
            mapAllNodes.emplace(newNode->hash, newNode);
        }
        // emplace returns iterator to new element or return iterator to existing element
        // use this to always get an element back that we want to insert in to
        auto res = vGroves.emplace(sub_block.hashPrevBlock, new CTailstormGrove());
        LOGA("added subblock %s to Grove %s \n", sub_block_hash.GetHex().c_str(), sub_block.hashPrevBlock.GetHex().c_str());
        return res.first->second->Insert(newNode);
    }

    bool Find(const uint256 &hash, CSubBlock &subblock)
    {
        READLOCK(cs_forest);
        std::map<uint256, CTreeNode*>::iterator iter = mapAllNodes.find(hash);
        if (iter != mapAllNodes.end())
        {
            subblock = iter->second->subblock;
            return true;
        }
        return false;
    }

    bool Contains(const uint256 &hash)
    {
        READLOCK(cs_forest);
        return (mapAllNodes.count(hash) != 0);
    }

    std::map<uint256, CTreeNode> GetAllNodes()
    {
        READLOCK(cs_forest);
        std::map<uint256, CTreeNode> allNodes;
        for (auto entry : mapAllNodes)
        {
            allNodes.emplace(entry.first, *entry.second);
        }
        return allNodes;
    }

    bool GetBestDagFor(const uint256 &prevBlockHash, std::set<CTreeNode> &dag)
    {
        READLOCK(cs_forest);
        auto iter = vGroves.find(prevBlockHash);
        if (iter == vGroves.end())
        {
            return false;
        }
        if (!iter->second->GetBestDag(dag))
        {
            return false;
        }
        return true;
    }

    bool GetBestTipHashFor(const uint256 &prevBlockHash, uint256& hash)
    {
        READLOCK(cs_forest);
        auto iter = vGroves.find(prevBlockHash);
        if (iter == vGroves.end())
        {
            return false;
        }
        if (!iter->second->GetBestTipHash(hash))
        {
            return false;
        }
        return true;
    }

};

extern CTailstormForest tailstormForest;

#endif
