// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_DAG_H
#define BITCOIN_TAILSTORM_DAG_H

// tailstorm file includes
#include "primitives/subblock.h"

// other bitcoin includes
#include "sync.h"

#include <deque>
#include <queue>
#include <set>

struct BestDagInfo
{
    std::vector<uint256> tip_hashes;
    std::vector<int16_t> compatible_dags;
    std::vector<int16_t> incompatible_dags;
};

class CDagNode;
typedef std::shared_ptr<CDagNode> CDagNodeRef;
template <typename Node>
static inline CDagNodeRef MakeDagNodeRef(Node &&nodeIn)
{
    return std::make_shared<CDagNode>(std::forward<Node>(nodeIn));
}

class CDagNode
{
public:
    uint256 hash; // the weakblock hash that is this node
    int16_t dag_id; // cannot be negative

    CSubBlockRef subblock;

    std::set<CDagNodeRef> ancestors; // should point to the nodes of the parentHashes
    std::set<CDagNodeRef> descendants; // points to the nodes of the children

private:
    CDagNode() {} // disable default constructor

public:
    CDagNode(CSubBlockRef _subblock)
    {
        if (_subblock)
           hash = _subblock->GetHash();

        subblock = _subblock;
        dag_id = -1;
    }

    friend bool operator<(const CDagNode &a, const CDagNode &b) { return a.hash < b.hash; }

    void AddAncestor(CDagNodeRef ancestor);
    void AddDescendant(CDagNodeRef descendant);
    bool IsBase();
    bool IsTip();
    bool IsValid();
};

class CTailstormDag
{
    friend class CTailstormDagSet;

protected:
    int16_t id; // should match the index of the vector in which this dag is in the dag set
    std::deque<CDagNodeRef> _dag;

public:
    // output spent, the tx hash it was spent in
    std::map<COutPoint, uint256> spent_outputs;
    uint64_t score;
    std::set<int16_t> incompatible_dags;

private:
    CTailstormDag() {} // disable default constructor

protected:
    void SetId(int16_t new_id);
    bool CheckForCompatibility(CDagNodeRef newNode);
    void UpdateCompatibility(const int16_t &new_id, const std::set<int16_t> &old_ids);
    void UpdateDagScore();

public:
    CTailstormDag(uint16_t _id, CDagNodeRef first_node)
    {
        id = _id;
        assert(id != -1);
        Insert(first_node);
    }
    bool Insert(CDagNodeRef new_node);
};

// this class can not have any public data members, all datamembers are
// protected by cs_dagset
class CTailstormDagSet
{
protected:
    CSharedCriticalSection cs_dagset;
    std::map<uint256, CDagNodeRef> mapAllNodes GUARDED_BY(cs_dagset);
    std::vector<CTailstormDag> vdags GUARDED_BY(cs_dagset);

private:
    void SetNewIds(std::priority_queue<int16_t> &removed_ids);
    void _SetNewIds(std::priority_queue<int16_t> &removed_ids);

protected:
    void _CreateNewDag(CDagNodeRef newNode);
    bool _MergeDags(std::set<int16_t> &tree_ids, int16_t &new_id);

public:
    CTailstormDagSet() { Clear(); }

    void Clear();

    size_t Size();

    CSubBlockRef Find(const uint256 &hash);
    bool Contains(const uint256 &hash);
    bool Insert(const CSubBlock &sub_block);
    bool GetBestDag(std::set<CDagNodeRef> &dag);
    BestDagInfo GetBestDagInfo();
    std::map<uint256, CDagNodeRef> GetAllNodes();
};

extern CTailstormDagSet tailstormDagSet;
extern CCriticalSection cs_tipDagCache;
extern std::map<uint256, CDagNodeRef> tipDagCache GUARDED_BY(cs_tipDagCache);

#endif
