// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCK_MINER_H
#define BITCOIN_TAILSTORM_BLOCK_MINER_H

// tailstorm file includes
#include "tailstorm/tailstorm.h"
#include "tailstorm/dag.h"

// other bitcoin includes
#include "miner_common.h"

#include <memory>
#include <stdint.h>

#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index_container.hpp"

class CBlockIndex;
class CChainParams;
class CReserveKey;
class CScript;
class CWallet;

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_coinbaseFlags;

extern std::atomic<int64_t> nTotalPackage;
extern std::atomic<int64_t> nTotalScore;
extern CTweak<bool> miningCPFP;

namespace Consensus
{
struct Params;
};

struct CTailstormBlockTemplate
{
    CBlockRef tailstormblock;
    CTailstormBlockTemplate() : tailstormblock(new CBlock()) {}
};

class TailstormBlockAssembler
{
private:
    const CChainParams &chainparams;

    // Configuration parameters for the block size
    uint64_t nBlockMaxSize, nBlockMinSize;

    // Information on the current status of the block
    uint64_t nBlockSize;
    uint64_t nBlockTx;
    unsigned int nBlockSigOps;
    CAmount nFees;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;

    uint64_t maxSigOpsAllowed = 0;

public:
    TailstormBlockAssembler(const CChainParams &chainparams);

    /** Internal method to construct a new block template */
    std::unique_ptr<CTailstormBlockTemplate> CreateNewTailstormBlock(int64_t coinbaseSize = -1);

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock(int64_t coinbaseSize = -1);

    // update stats after adding tx to the block
    void UpdateBlockStats(CTransactionRef tx, CCoinsViewCache &cache);


    /** Bytes to reserve for coinbase and block header */
    uint64_t reserveBlockSize(int64_t coinbaseSize = -1);
    /** Constructs a coinbase transaction */
    CTransactionRef coinbaseTx(int nHeight, CAmount nValue, const std::set<CTreeNodeRef> &dag);
};

#endif
