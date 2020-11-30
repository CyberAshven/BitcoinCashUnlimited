// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "compactrelay.h"

CCriticalSection cs_compact_reconstruct;
// blocks that are currently being reconstructed.
std::map<NodeId, std::map<uint256, std::shared_ptr<BobCompactBlock> > > mapBobCompactBlocksReconstruct GUARDED_BY(cs_compact_reconstruct);

std::shared_ptr<BobCompactBlock> SetCompactBlockToReconstruct(CNode *pfrom, const BobCompactBlock &block)
{
    LOCK(cs_compact_reconstruct);
    // If another thread has already created an instance then return it.
    // Currently we can only have one block hash in flight per node so make sure it's the same hash.
    std::shared_ptr<BobCompactBlock> existing_entry = GetCompactBlockToReconstruct(pfrom, block.GetHash());
    if (existing_entry != nullptr)
    {
        return existing_entry;
    }
    // Otherwise, start with a fresh instance.
    // Store and empty block which can be used later
    std::shared_ptr<BobCompactBlock> pblock = std::make_shared<BobCompactBlock>(block);
    // unless we run out of memory, emplace should never fail
    auto newKey = mapBobCompactBlocksReconstruct.emplace(pfrom->GetId(), std::map<uint256, std::shared_ptr<BobCompactBlock> >());
    newKey.first->second.emplace(block.GetHash(), pblock);
    return pblock;
}

std::shared_ptr<BobCompactBlock> GetCompactBlockToReconstruct(CNode *pfrom, const uint256 &hash)
{
    // Retrieve a current instance of a block being reconstructed. This is typically used
    // when we have received the response of a re-request for more transactions.
    LOCK(cs_compact_reconstruct);
    auto key_node = mapBobCompactBlocksReconstruct.find(pfrom->GetId());
    if (key_node != mapBobCompactBlocksReconstruct.end())
    {
        auto key_hash = key_node->second.find(hash);
        if (key_hash != key_node->second.end())
        {
            return key_hash->second;
        }
    }
    return nullptr;
}

void ClearCompactBlockToReconstruct(NodeId id, const uint256 &hash)
{
    LOCK(cs_compact_reconstruct);
    auto key = mapBobCompactBlocksReconstruct.find(id);
    if (key != mapBobCompactBlocksReconstruct.end())
    {
        key->second.erase(hash);
    }
}
