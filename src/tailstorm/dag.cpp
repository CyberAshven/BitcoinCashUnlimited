// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "dag.h"

// other bitcoin includes
#include "consensus/consensus.h"
#include "txmempool.h"

bool CTailstormTree::CheckForCompatibility(CTreeNodeRef newNode)
{
    // TODO:  ptschip - tailstorm tree objects have no internal lock?
    for (auto &tx : newNode->subblock->vtx)
    {
        for (auto &input : tx->vin)
        {
            if (spent_outputs.count(input.prevout) != 0)
            {
                if (spent_outputs[input.prevout] != tx->GetHash())
                {
                    return false;
                }
            }
        }
    }
    return true;
}

bool CTailstormTree::Insert(CTreeNodeRef new_node)
{
    std::map<COutPoint, uint256> new_spends;
    for (auto &tx : new_node->subblock->vtx)
    {
        if (tx->IsProofBase() == false)
        {
            for (auto &input : tx->vin)
            {
                // TODO : change to contains in c++17
                if (spent_outputs.count(input.prevout) != 0)
                {
                    if (spent_outputs[input.prevout] != tx->GetHash())
                    {
                        return false;
                    }
                }
                new_spends.emplace(input.prevout, tx->GetHash());
            }
        }
    }
    // change to merge in c++17
    spent_outputs.insert(new_spends.begin(), new_spends.end());
    _dag.emplace_back(new_node);
    //UpdateDagScore();
    return true;
}

void CTailstormGrove::_CreateNewTree(CTreeNodeRef newNode)
{
    AssertWriteLockHeld(cs_grove);
    uint16_t new_id = 0;
    newNode->dag_id = new_id;
    _tree.Insert(newNode);
    for (auto &tx : newNode->subblock->vtx)
    {
        mempool.UpdateTransactionDagInfo(tx->GetHash(), new_id, true);
    }
}

void CTailstormGrove::Clear()
{
    // should always have cs_forest lock because this should only be called from
    // within a clear method at the forest level
    AssertWriteLockHeld(tailstormForest.cs_forest);
    WRITELOCK(cs_grove);
    // delete all of the nodes in this grove, this deletes the
    // nodes in mapAllNodes which should be cleared using the set of hashes this
    // method returns
    for (auto &entry : mapAllGroveNodes)
    {
        tailstormForest.mapAllNodes.erase(entry.first);
    }
    mapAllGroveNodes.clear();
    mapUnusedNodes.clear();
}

void CTailstormGrove::_CheckOrphans(const uint256 &hash)
{
    uint256 ancestorHash;

    for (auto iter = mapUnusedNodes.begin(); iter != mapUnusedNodes.end();)
    {
        if (iter->second->subblock->GetAncestorHash(ancestorHash))
        {
            if (ancestorHash == hash)
            {
                if (_InsertIntoTree(iter->second))
                {
                    iter = mapUnusedNodes.erase(iter);
                    continue;
                }
            }
        }
        ++iter;
    }
}

bool CTailstormGrove::_InsertIntoTree(CTreeNodeRef newNode)
{
    AssertWriteLockHeld(cs_grove);
    // First check if we already have this in tree so we don't add it again. We must
    // not have duplicates in the tree or else we will end up add two of the same subblock
    // to the tailstorm coinbase.
    //
    // Return true if we already have it so that any orphans can be erased.
    for (auto &node : _tree._dag)
    {
        if (node->subblock->GetHash() == newNode->subblock->GetHash())
            return true;
    }

    mapAllGroveNodes.emplace(newNode->hash, newNode);
    bool AddToTree = true;
    uint256 ancestorHash = uint256();
    if (_tree._dag.size() == 0)
    {
        // minimum of 1 hash, which is null if no ancestors
        if (newNode->subblock->GetAncestorHash(ancestorHash))
        {
            LOGA("%s(): ERROR, subblock %s has ancestor hashes but there are no nodes in the tree\n",
                __func__, newNode->hash.GetHex().c_str());
            return false;
        }
        // newNode id is set inside _CreateNewTree
        _CreateNewTree(newNode);
        return true;
    }
    // check that we have all ancestor treenodes and that they are in the tree
    CTreeNodeRef ancestor = nullptr;
    if (newNode->subblock->GetAncestorHash(ancestorHash))
    {
        std::map<uint256, CTreeNodeRef>::iterator ancestor_iter = mapAllGroveNodes.find(ancestorHash);
        if (ancestor_iter == mapAllGroveNodes.end())
        {
            // TODO : A subblock is missing, try to re-request it or something
            LOGA("%s(): ERROR, subblock %s references missing ancestor subblock %s\n",
                __func__, newNode->hash.GetHex().c_str(), ancestorHash.GetHex().c_str());
            return false;
        }
        bool found = false;
        for (const auto node : _tree._dag)
        {
            if (node->hash == ancestorHash)
            {
                // use a pointer to the node already inserted in mapAllGroveNodes to avoid obj duplication
                // CTreeNodeRef ancestor = ancestor_iter->second;
                ancestor = ancestor_iter->second;
                found = true;
                break;
            }
        }
        if (found == false)
        {
            LOGA("%s(): WARNING, subblock %s references ancestor subblock %s that is not in tree\n",
                __func__, newNode->hash.GetHex().c_str(), ancestorHash.GetHex().c_str());
            AddToTree = false;
        }
    }
    // add ancestor information regardless
    if (ancestor != nullptr)
    {
        newNode->AddAncestor(ancestor);
        newNode->height = ancestor->height + 1;
    }
    if (!_tree.CheckForCompatibility(newNode))
    {
        LOGA("%s(): subblock %s is incompatible with tree \n", __func__, newNode->hash.GetHex().c_str());
        AddToTree = false;
    };
    if (AddToTree == false)
    {
        mapUnusedNodes.emplace(newNode->hash, newNode);
        return true;
    }
    if (ancestor)
    {
        ancestor->AddDescendant(newNode);
    }
    newNode->dag_id = 0;
    if (!_tree.Insert(newNode))
    {
        LOGA("%s(): failed to add subblock %s to tree %s \n", __func__,
            newNode->hash.GetHex().c_str(), newNode->subblock->hashPrevBlock.GetHex().c_str());
        return false;
    }
    // once we have inserted the subblock into a dag, we should update the
    // mempool with information about which dag the txx went into
    for (auto &tx : newNode->subblock->vtx)
    {
        mempool.UpdateTransactionDagInfo(tx->GetHash(), newNode->dag_id, true);
    }
    return true;
}

bool CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    WRITELOCK(cs_grove);
    bool ret = _InsertIntoTree(newNode);
    if (ret)
    {
        _CheckOrphans(newNode->hash);
    }
    return ret;
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag)
{
    READLOCK(cs_grove);
    if (_tree._dag.size() < TAILSTORM_K)
    {
        return false;
    }
    size_t nodeCt = 0;
    for (auto& node : _tree._dag)
    {
        dag.emplace(node);
        nodeCt++;
        //TODO: Do something more sophisticated to handle cases where there are more
        // nodes than are necessary to assemble a block
        if (nodeCt == TAILSTORM_K)
            break;
    }
    if (dag.size() < TAILSTORM_K)
    {
        for (auto& node : _tree._dag)
           printf("subblocks in failed dag %s\n", node->subblock->GetHash().ToString().c_str());


    }

    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256& hash)
{
    READLOCK(cs_grove);
    unsigned int bestHeight = 0;
    for (auto &node : _tree._dag)
    {
        if (node->IsTip())
        {
            if (node->height > bestHeight)
            {
                hash = node->hash;
                bestHeight = node->height;
            }
            else if (node->height == bestHeight)
            {
                if (node->hash < hash)
                {
                    hash = node->hash;
                }
            }
        }
    }
    return true;
}
