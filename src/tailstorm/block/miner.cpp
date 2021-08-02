// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "miner.h"
#include "validation.h"

// other bitcoin includes
#include "amount.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "hashwrapper.h"
#include "main.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "respend/respenddetector.h"
#include "script/standard.h"
#include "timedata.h"
#include "txmempool.h"
#include "unlimited.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation/forks.h"
#include "validation/validation.h"
#include "validationinterface.h"

#include <algorithm>
#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>
//#include <coz.h>
#include <queue>
#include <thread>

/** Maximum number of failed attempts to insert a package into a block */
static const unsigned int MAX_PACKAGE_FAILURES = 5;
extern CTweak<unsigned int> xvalTweak;
extern CTailstormDagSet tailstormDagSet;

/*CTailstormBlockAssembler*/

TailstormBlockAssembler::TailstormBlockAssembler(const CChainParams &_chainparams)
    : chainparams(_chainparams), nBlockSize(0), nBlockTx(0), nBlockSigOps(0), nFees(0), nHeight(0), nLockTimeCutoff(0),
      lastFewTxs(0), blockFinished(false)
{
    // Largest block you're willing to create:
    nBlockMaxSize = maxGeneratedBlock;
    // Core:
    // nBlockMaxSize = GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    // nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);
}

void TailstormBlockAssembler::resetBlock(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    inBlock.clear();

    nBlockSize = reserveBlockSize(scriptPubKeyIn, coinbaseSize); // Core: 1000
    nBlockSigOps = 100; // Reserve 100 sigops for miners to use in their coinbase transaction

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;

    lastFewTxs = 0;
    blockFinished = false;
}

uint64_t TailstormBlockAssembler::reserveBlockSize(const CScript &scriptPubKeyIn, int64_t coinbaseSize)
{
    CBlockHeader h;
    uint64_t nHeaderSize;

    // BU add the proper block size quantity to the actual size
    nHeaderSize = ::GetSerializeSize(h, SER_NETWORK, PROTOCOL_VERSION);
    assert(nHeaderSize == 80); // BU always 80 bytes
    nHeaderSize += 5; // tx count varint - 5 bytes is enough for 4 billion txs; 3 bytes for 65535 txs

    return nHeaderSize;
}

CTransactionRef TailstormBlockAssembler::coinbaseTx(const CScript &scriptPubKeyIn, int _nHeight, CAmount nValue, const std::set<CDagNode> &dag)
{
    CMutableTransaction tx;

    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << _nHeight << OP_0;
    // set the vout to be tailstorm K at least
    tx.vout.resize(TAILSTORM_K);
    CAmount valuePer = nValue / TAILSTORM_K;
    unsigned int i = 0;
    std::set<CDagNode>::iterator iter = dag.begin();
    CAmount total_paid = 0;
    while (i < TAILSTORM_K && iter != dag.end())
    {
        tx.vout[i].scriptPubKey = (*iter).subblock.vtx[0]->vin[0].scriptSig;
        tx.vout[i].nValue = valuePer;
        total_paid = total_paid + valuePer;
	    ++i;
    }
    unsigned int k = 0;
    unsigned int zero_indexed_K = TAILSTORM_K - 1;
    while (total_paid < nValue)
    {
        tx.vout[k % zero_indexed_K].nValue = tx.vout[k % zero_indexed_K].nValue + 1;
        total_paid++;
    }
    // sanity check, this should never fail
    assert(total_paid == nValue);

    // BU005 add block size settings to the coinbase
    std::string cbmsg = FormatCoinbaseMessage(BUComments, minerComment);
    const char *cbcstr = cbmsg.c_str();
    std::vector<unsigned char> vec(cbcstr, cbcstr + cbmsg.size());
    {
        LOCK(cs_coinbaseFlags);
        COINBASE_FLAGS = CScript() << vec;
        // Chop off any extra data in the COINBASE_FLAGS so the sig does not exceed the max.
        // we can do this because the coinbase is not a "real" script...
        if (tx.vin[0].scriptSig.size() + COINBASE_FLAGS.size() > MAX_COINBASE_SCRIPTSIG_SIZE)
        {
            COINBASE_FLAGS.resize(MAX_COINBASE_SCRIPTSIG_SIZE - tx.vin[0].scriptSig.size());
        }

        tx.vin[0].scriptSig = tx.vin[0].scriptSig + COINBASE_FLAGS;
    }

    // Make sure the coinbase is big enough.
    uint64_t nCoinbaseSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
    if (nCoinbaseSize < MIN_TX_SIZE && IsNov2018Activated(Params().GetConsensus(), chainActive.Tip()))
    {
        tx.vin[0].scriptSig << std::vector<uint8_t>(MIN_TX_SIZE - nCoinbaseSize - 1);
    }

    return MakeTransactionRef(std::move(tx));
}

std::unique_ptr<CTailstormBlockTemplate> TailstormBlockAssembler::CreateNewTailstormBlock(const CScript &scriptPubKeyIn,
    int64_t coinbaseSize)
{
    resetBlock(scriptPubKeyIn, coinbaseSize);

    // The constructed block template
    std::unique_ptr<CTailstormBlockTemplate> pblocktemplate(new CTailstormBlockTemplate());

    CTailstormBlock *pblock = pblocktemplate->tailstormblock.get();

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LOCK(cs_main);
    CBlockIndex *pindexPrev = chainActive.Tip();
    assert(pindexPrev); // can't make a new block if we don't even have the genesis block
    maxSigOpsAllowed = maxSigChecks.Value();

    {
        // we must get the best dag before locking mempool because we can not recursively lock mempool
        std::set<CDagNode> bestdag;
        if (tailstormDagSet.GetBestDag(bestdag) == false)
        {
            return nullptr;
        }
        READLOCK(mempool.cs_txmempool);
        nHeight = pindexPrev->nHeight + 1;

        pblock->nTime = GetAdjustedTime();
        pblock->nVersion = UnlimitedComputeBlockVersion(pindexPrev, chainparams.GetConsensus(), pblock->nTime);
        // -regtest only: allow overriding block.nVersion with
        // -blockversion=N to test forking scenarios
        if (chainparams.MineBlocksOnDemand())
            pblock->nVersion = GetArg("-blockversion", pblock->nVersion);

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        nLockTimeCutoff =
            (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : pblock->GetBlockTime();

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LOGA("CreateNewTailstormBlock: total size %llu txs: %llu of %llu fees: %lld sigops %u\n", nBlockSize, nBlockTx,
            mempool._size(), nFees, nBlockSigOps);

        // Populate vdag with subblocks and create coinbase tx
        for (auto &dagnode : bestdag)
        {
            pblock->vdag.push_back(std::make_shared<CSubBlock>(dagnode.subblock));
            pblock->subblockHashes.emplace(dagnode.subblock.GetHash());
            pblock->subblockNTxMap[dagnode.subblock.GetHash()] = dagnode.subblock.vtx.size();
        }
        pblock->vtx[0] =
            coinbaseTx(scriptPubKeyIn, nHeight, nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus()), bestdag);
        pblock->UpdateTxLists();

        std::set<uint256> blockTxHashes;
        for (auto &tx : pblock->vtx)
        {
            if (tx != nullptr)
                blockTxHashes.insert(tx->GetHash());
        }

        // Search for txs in mempool and add them to vtxe
        AssertLockHeld(mempool.cs_txmempool);
        std::vector<const CTxMemPoolEntry *> vtxe;
        std::map<uint256, const CTxMemPoolEntry *> vtxeMap;
		// TODO: Griffith to make this more efficient after refactoring DAG
        for (CTxMemPool::indexed_transaction_set::const_iterator it = mempool.mapTx.begin(); it != mempool.mapTx.end(); it++)
        {
            if (blockTxHashes.count(it->GetSharedTx()->GetHash()) > 0)
            {
                AddToBlock(&vtxe, it);
                vtxeMap[vtxe.back()->GetSharedTx()->GetHash()] = vtxe.back();
            }
        }

        for (auto &tx : pblock->vtx)
        {
            if (tx->IsCoinBase())
            {
                continue;
            }
            else if (tx->IsProofBase())
            {
                pblocktemplate->vTxFees.push_back(0);
                pblocktemplate->vTxSigOps.push_back(0);
            }
            else
            {
                pblocktemplate->vTxFees.push_back(vtxeMap[tx->GetHash()]->GetFee());
                pblocktemplate->vTxSigOps.push_back(vtxeMap[tx->GetHash()]->GetSigOpCount());
            }

        }
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        // update the time
        int64_t nOldTime = pblock->nTime;
        int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());
        if (nOldTime < nNewTime)
        {
            pblock->nTime = nNewTime;
        }
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock->GetBlockTime(), chainparams.GetConsensus());
        pblocktemplate->vTxSigOps[0] = 0;
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    }

    CValidationState state;
    if (!TestTailstormBlockValidity(state, chainparams, *pblock, pindexPrev, false, false))
    {
        throw std::runtime_error(
            strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }

    return pblocktemplate;
}

void TailstormBlockAssembler::AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPool::txiter iter)
{
    const CTxMemPoolEntry &tmp = *iter;
    vtxe->push_back(&tmp);
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority)
    {
        double dPriority = iter->GetPriority(nHeight);
        CAmount dummy;
        mempool._ApplyDeltas(iter->GetTx().GetHash(), dPriority, dummy);
        LOGA("priority %.1f fee %s txid %s\n", dPriority,
            CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString().c_str(),
            iter->GetTx().GetHash().ToString().c_str());
    }
}

void TailstormBlockAssembler::AddToBlock(std::vector<const CTxMemPoolEntry *> *vtxe, CTxMemPoolEntry *entry)
{
    vtxe->push_back(entry);
    nBlockSize += entry->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += entry->GetSigOpCount();
    nFees += entry->GetFee();
    CTxMemPool::txiter txiter = mempool.mapTx.find(entry->GetSharedTx()->GetHash());
    inBlock.insert((CTxMemPool::txiter)(txiter));
}
