// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_COMMON_H
#define BITCOIN_MINER_COMMON_H

#include "chain.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "txmempool.h"

static const bool DEFAULT_PRINTPRIORITY = false;

/** Comparator for CTxMemPool::txiter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct CompareCTxMemPoolIter
{
    bool operator()(const CTxMemPool::txiter &a, const CTxMemPool::txiter &b) const { return &(*a) < &(*b); }
};

/** A comparator that sorts transactions based on number of ancestors.
 * This is sufficient to sort an ancestor package in an order that is valid
 * to appear in a block.
 */
struct CompareTxIterByAncestorCount
{
    bool operator()(const CTxMemPool::txiter &a, const CTxMemPool::txiter &b)
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors())
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        return CTxMemPool::CompareIteratorByHash()(a, b);
    }
};

struct NumericallyLessTxHashComparator
{
public:
    bool operator()(const CTxMemPoolEntry *a, const CTxMemPoolEntry *b) const
    {
        return a->GetTx().GetHash() < b->GetTx().GetHash();
    }
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const
    {
        return a->GetHash() < b->GetHash();
    }
};

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev);

/** Make a block template to send to miners. */
// implemented in mining.cpp
UniValue mkblocktemplate(const UniValue &params,
    int64_t coinbaseSize = -1,
    CBlock *pblockOut = nullptr,
    const CScript &coinbaseScript = CScript());

#endif
