// Copyright (c) 2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKDB_BLOCKCACHE_H
#define BLOCKDB_BLOCKCACHE_H

#include "main.h"
#include "primitives/block.h"
#include "sync.h"

#include <unordered_map>


class CBlockCache
{
private:
    enum BlockType
    {
        CBLOCK,
        CSUBBLOCK,
    };

    struct CCacheEntry
    {
        int64_t nEntryTime;
        uint64_t nHeight;
        BlockType blockType;
        uint64_t blockSize;
        std::shared_ptr<void> pblock;
    };

    mutable CSharedCriticalSection cs_blockcache;
    /** an in memory cache of blocks */
    std::unordered_map<uint256, CCacheEntry, BlockHasher> cache GUARDED_BY(cs_blockcache);

    /** Current in memory byte size of the block cache */
    int64_t nBytesCache GUARDED_BY(cs_blockcache) = 0;

    /** Maximum allowed byte size of the cache */
    int64_t nMaxSizeCache GUARDED_BY(cs_blockcache) = 0;

    /** how much to increment or decrement the cache size at one time */
    const uint64_t nIncrement = 1;

public:
    /** Keep track of recent subblocks that were valid and fully accepted */
    CRollingFastFilter<4 * 1024 * 1024> filterRecentSubBlock;

    CBlockCache(){};

    /** Add block to the block cache */
    void AddBlock(CBlockRef pblock, uint64_t nHeight);
    /** Add subblock to the block cache */
    void AddBlock(CSubBlockRef pblock, uint64_t nHeight);

    /** Add any block to the block cache */
    void _AddBlock(const BlockType BlockType,
        const uint256 &hash,
        const std::shared_ptr<void> pblock,
        const uint64_t nHeight,
        const uint64_t blockSize);

    /** Find and return a block from the block cache */
    bool GetBlock(const uint256 &hash, CBlockRef &pblock) const;

    /** Find and return a subblock from the block cache */
    bool GetBlock(const uint256 &hash, CSubBlockRef &pblock) const;

    /** Remove a block from the block cache */
    void EraseBlock(const uint256 &hash);


private:
    /** Adjust the block download window */
    void _CalculateDownloadWindow(const int64_t &blockSize);

    /** Trim the cache when necessary */
    void _TrimCache();
};
extern CBlockCache blockcache;

#endif // BLOCKDB_BLOCKCACHE_H
