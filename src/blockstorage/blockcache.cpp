// Copyright (c) 2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockcache.h"

#include "main.h"
#include "requestManager.h"

void CBlockCache::AddBlock(CBlockRef pblock, uint64_t nHeight)
{
    _AddBlock(pblock->GetHash(), BlockType::CBLOCK, pblock->GetBlockSize(), pblock, nHeight);
}

void CBlockCache::AddBlock(CTailstormBlockRef pblock, uint64_t nHeight)
{
    _AddBlock(pblock->GetHash(), BlockType::CTAILSTORMBLOCK, pblock->GetBlockSize(), pblock, nHeight);
}

bool CBlockCache::GetBlock(const uint256 &hash, CBlockRef &pblock) const
{
    pblock = std::static_pointer_cast<CBlock>(_GetBlock(hash, BlockType::CBLOCK));
    return pblock != nullptr;
}
bool CBlockCache::GetBlock(const uint256 &hash, CTailstormBlockRef &pblock) const
{
    pblock = std::static_pointer_cast<CTailstormBlock>(_GetBlock(hash, BlockType::CTAILSTORMBLOCK));
    return pblock != nullptr;
}

void CBlockCache::_AddBlock(const uint256 &hash, const BlockType &blockType, const uint64_t &blockSize, std::shared_ptr<void> pblock, uint64_t nHeight)
{
    WRITELOCK(cs_blockcache);

    // Only add a new cache block if the cache size is large enough. Always limit the newer blocks
    // instead of trimming the older ones then we will never end up using any of the cache for processing blocks
    // but will instead just keep adding and removing blocks that never get used.
    int64_t nMaxMempool = GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
    nMaxSizeCache = nMaxMempool - mempool.DynamicMemoryUsage();
    if (nMaxSizeCache < 0)
    {
        nMaxSizeCache = nMaxMempool;
    }
    // Add the block to the cache if there is room.
    _CalculateDownloadWindow(blockSize);
    if ((nBytesCache + (int64_t)blockSize < nMaxSizeCache) &&
        (cache.size() + 1 < requester.BLOCK_DOWNLOAD_WINDOW.load()))
    {
        auto ret = cache.insert({hash, {GetTimeMillis(), nHeight, blockType, blockSize, pblock}});
        if (ret.second == true)
        {
            nBytesCache += blockSize;
        }
    }
    _TrimCache();
    LOG(IBD, "Block Cache bytes: %d,  num blocks: %d, block download window: %d\n", nBytesCache, cache.size(),
        requester.BLOCK_DOWNLOAD_WINDOW.load());
}

std::shared_ptr<void> CBlockCache::_GetBlock(const uint256 &hash, const BlockType &blockType) const
{
    READLOCK(cs_blockcache);
    auto iter = cache.find(hash);
    if (iter != cache.end())
    {
        if (iter->second.blockType == blockType)
        {
            return iter->second.pblock;
        }
    }
    return nullptr;
}

void CBlockCache::EraseBlock(const uint256 &hash)
{
    WRITELOCK(cs_blockcache);
    auto iter = cache.find(hash);
    if (iter != cache.end())
    {
        nBytesCache -= iter->second.blockSize;
        cache.erase(iter);
        LOG(IBD, "Erased Block from cache - current size: %d,  num blocks: %d\n", nBytesCache, cache.size());
    }
}

void CBlockCache::_TrimCache()
{
    AssertWriteLockHeld(cs_blockcache);

    // If the chain is fully synced then we only allow, at most, the last
    // few blocks in the chain to be saved.
    uint64_t nHeightToKeep = DEFAULT_BLOCKS_FROM_TIP;
    if (IsChainNearlySyncd() && cache.size() > nHeightToKeep)
    {
        uint64_t nMinHeight = chainActive.Height() - nHeightToKeep;
        auto mi = cache.begin();
        while (mi != cache.end())
        {
            LOG(IBD, "Cache item height %d nMinheight %d\n", mi->second.nHeight, nMinHeight);
            if (mi->second.nHeight <= nMinHeight)
            {
                nBytesCache -= mi->second.blockSize;
                mi = cache.erase(mi);
            }
            else
            {
                mi++;
            }
        }
    }
    // This should never happen but as a safeguard during IBD we can trim the cache
    // if it exceeds our maximum by 5%.
    else if (IsInitialBlockDownload() && (nBytesCache > nMaxSizeCache * 1.05))
    {
        // Assert if we're running debug since we should never get here.
        DbgAssert(!"In Memory Block Cache has gotten too big", );

        // Just trim any entries
        auto mi = cache.begin();
        while (nBytesCache > nMaxSizeCache)
        {
            nBytesCache -= mi->second.blockSize;
            mi = cache.erase(mi);
        }
    }
}

void CBlockCache::_CalculateDownloadWindow(const int64_t &blockSize)
{
    AssertWriteLockHeld(cs_blockcache);

    // Adjust the block download window depending on how much memory is available
    if (cache.size() + nIncrement >= requester.BLOCK_DOWNLOAD_WINDOW.load() && nBytesCache + blockSize < nMaxSizeCache)
    {
        if (requester.BLOCK_DOWNLOAD_WINDOW.load() <= DEFAULT_BLOCK_DOWNLOAD_WINDOW)
        {
            requester.BLOCK_DOWNLOAD_WINDOW.fetch_add(nIncrement);
        }
    }
    else if (nBytesCache + blockSize > nMaxSizeCache)
    {
        if (cache.size() > nIncrement)
        {
            requester.BLOCK_DOWNLOAD_WINDOW.store(cache.size());
        }
        else
        {
            requester.BLOCK_DOWNLOAD_WINDOW.store(nIncrement); // make sure we don't go to zero
        }
    }
    else
    {
        if (cache.size() > 0)
        {
            const uint64_t nAvgBlockSizeInCache = nBytesCache / cache.size();
            if (nAvgBlockSizeInCache > 0)
            {
                uint64_t nWindow = nMaxSizeCache / nAvgBlockSizeInCache;
                nWindow = std::min(nWindow, (uint64_t)DEFAULT_BLOCK_DOWNLOAD_WINDOW);
                requester.BLOCK_DOWNLOAD_WINDOW.store(nWindow);
            }
        }
    }
}
