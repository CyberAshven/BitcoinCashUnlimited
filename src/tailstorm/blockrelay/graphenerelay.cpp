// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "graphenerelay.h"

CCriticalSection cs_sb_graphene_sender;
std::map<NodeId, std::shared_ptr<CSBGrapheneBlock> > mapSBGrapheneSentBlocks GUARDED_BY(cs_sb_graphene_sender);

CCriticalSection cs_graphene_reconstruct;
// blocks that are currently being reconstructed.
std::map<NodeId, std::map<uint256, std::shared_ptr<CSBGrapheneBlock> > > mapSubblockGrapheneBlocksReconstruct GUARDED_BY(cs_graphene_reconstruct);

void SetSentSBGrapheneBlocks(NodeId id, CSBGrapheneBlock &grapheneBlock)
{
    LOCK(cs_sb_graphene_sender);
    mapSBGrapheneSentBlocks[id] = std::make_shared<CSBGrapheneBlock>(grapheneBlock);
}

std::shared_ptr<CSBGrapheneBlock> GetSentSBGrapheneBlocks(NodeId id)
{
    LOCK(cs_sb_graphene_sender);

    auto it = mapSBGrapheneSentBlocks.find(id);
    if (it != mapSBGrapheneSentBlocks.end())
        return it->second;
    else
        return std::shared_ptr<CSBGrapheneBlock>();
}

void ClearSentSBGrapheneBlocks(NodeId id)
{
    LOCK(cs_sb_graphene_sender);
    mapSBGrapheneSentBlocks.erase(id);
}

std::shared_ptr<CSBGrapheneBlock> SetSBGBlockToReconstruct(CNode *pfrom, const CSBGrapheneBlock &block)
{
    LOCK(cs_graphene_reconstruct);
    // If another thread has already created an instance then return it.
    // Currently we can only have one block hash in flight per node so make sure it's the same hash.
    std::shared_ptr<CSBGrapheneBlock> existing_entry = GetSBGBlockToReconstruct(pfrom, block.GetHash());
    if (existing_entry != nullptr)
    {
        return existing_entry;
    }
    // Otherwise, start with a fresh instance.
    // Store and empty block which can be used later
    std::shared_ptr<CSBGrapheneBlock> pblock = std::make_shared<CSBGrapheneBlock>(block);
    // unless we run out of memory, emplace should never fail
    auto newKey = mapSubblockGrapheneBlocksReconstruct.emplace(pfrom->GetId(), std::map<uint256, std::shared_ptr<CSBGrapheneBlock> >());
    newKey.first->second.emplace(block.GetHash(), pblock);
    return pblock;
}

std::shared_ptr<CSBGrapheneBlock> GetSBGBlockToReconstruct(CNode *pfrom, const uint256 &hash)
{
    // Retrieve a current instance of a block being reconstructed. This is typically used
    // when we have received the response of a re-request for more transactions.
    LOCK(cs_graphene_reconstruct);
    auto key_node = mapSubblockGrapheneBlocksReconstruct.find(pfrom->GetId());
    if (key_node != mapSubblockGrapheneBlocksReconstruct.end())
    {
        auto key_hash = key_node->second.find(hash);
        if (key_hash != key_node->second.end())
        {
            return key_hash->second;
        }
    }
    return nullptr;
}

void ClearSBGBlockToReconstruct(NodeId id, const uint256 &hash)
{
    LOCK(cs_graphene_reconstruct);
    auto key = mapSubblockGrapheneBlocksReconstruct.find(id);
    if (key != mapSubblockGrapheneBlocksReconstruct.end())
    {
        key->second.erase(hash);
    }
}
