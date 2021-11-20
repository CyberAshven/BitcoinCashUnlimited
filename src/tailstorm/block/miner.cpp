// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "miner.h"

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
#include "tailstorm/tailstorm.h"
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

struct TxEncodeHashComparator
{
public:
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const { return a->GetHash() < b->GetHash(); }
};

/*CTailstormBlockAssembler*/

TailstormBlockAssembler::TailstormBlockAssembler(const CChainParams &_chainparams)
    : chainparams(_chainparams), nBlockSize(0), nBlockTx(0), nBlockSigOps(0), nFees(0), nHeight(0), nLockTimeCutoff(0)
{
    // Largest block you're willing to create:
    nBlockMaxSize = chainActive.Tip()->GetNextMaxBlockSize();
    if (nBlockMaxSize > maxGeneratedBlock)
        nBlockMaxSize = maxGeneratedBlock;
}

void TailstormBlockAssembler::resetBlock(int64_t coinbaseSize)
{
    nBlockSize = reserveBlockSize(coinbaseSize); // Core: 1000
    nBlockSigOps = 100; // Reserve 100 sigops for miners to use in their coinbase transaction

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

uint64_t TailstormBlockAssembler::reserveBlockSize(int64_t coinbaseSize)
{
    CBlockHeader h;
    uint64_t nHeaderSize;

    // BU add the proper block size quantity to the actual size
    nHeaderSize = ::GetSerializeSize(h, SER_NETWORK, PROTOCOL_VERSION);
    //  assert(nHeaderSize == 80); // BU always 80 bytes
    // tx count varint - 5 bytes is enough for 4 billion txs; 3 bytes for 65535 txs  - TODO: ptschip is this correct
    nHeaderSize += 5;
    // or do we need to account for the ntx map?
    /*  TODO: ptschip - this was left missing in the tailstorm file, should we add it again?
        // This serializes with output value, a fixed-length 8 byte field, of zero and height, a serialized CScript
        // signed integer taking up 4 bytes for heights 32768-8388607 (around the year 2167) after which it will use 5
        nCoinbaseSize = ::GetSerializeSize(coinbaseTx(scriptPubKeyIn, 400000, 0), SER_NETWORK, PROTOCOL_VERSION);

        if (coinbaseSize >= 0) // Explicit size of coinbase has been requested
        {
            nCoinbaseReserve = (uint64_t)coinbaseSize;
        }
        else
        {
            nCoinbaseReserve = coinbaseReserve.Value();
        }

        // BU Miners take the block we give them, wipe away our coinbase and add their own.
        // So if their reserve choice is bigger then our coinbase then use that.
        nCoinbaseSize = std::max(nCoinbaseSize, nCoinbaseReserve);

        return nHeaderSize + nCoinbaseSize;
    */


    return nHeaderSize;
}

CTransactionRef TailstormBlockAssembler::coinbaseTx(int _nHeight, CAmount nValue, const std::set<CTreeNodeRef> &dag)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << _nHeight << OP_0;
    // set the vout to be tailstorm K at least
    assert(dag.size() >= TAILSTORM_K);
    tx.vout.resize(TAILSTORM_K);
    CAmount valuePer = nValue / TAILSTORM_K;
    std::set<CTreeNodeRef>::iterator iter = dag.begin();
    CAmount total_paid = 0;
    unsigned int i = 0;
    while (i < TAILSTORM_K && iter != dag.end())
    {
        tx.vout[i].scriptPubKey = (*iter)->subblock->vtx[0]->vin[0].scriptSig;
        tx.vout[i].nValue = valuePer;
        total_paid = total_paid + valuePer;
        ++i;
        ++iter;
    }
    // any remainder gets added to the first index
    CAmount remainder = nValue - total_paid;
    if (remainder > 0)
    {
        tx.vout[0].nValue = tx.vout[0].nValue + remainder;
        // for the following assert
        total_paid = total_paid + remainder;
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

std::unique_ptr<CTailstormBlockTemplate> TailstormBlockAssembler::CreateNewTailstormBlock(int64_t coinbaseSize)
{
    resetBlock(coinbaseSize);
    CCoinsViewCache cache(pcoinsTip);

    // The constructed block template
    std::unique_ptr<CTailstormBlockTemplate> pblocktemplate(new CTailstormBlockTemplate());

    CBlock *pblock = pblocktemplate->tailstormblock.get();

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();

    LOCK(cs_main);
    CBlockIndex *pindexPrev = chainActive.Tip();
    assert(pindexPrev); // can't make a new block if we don't even have the genesis block

    maxSigOpsAllowed = GetMaxBlockSigChecks(pindexPrev->GetNextMaxBlockSize());
    {
        // we must get the best dag before locking mempool because we can not recursively lock mempool
        std::set<CTreeNodeRef> bestdag;
        if (tailstormForest.GetBestDagFor(pindexPrev->GetBlockHash(), bestdag) == false)
        {
            return nullptr;
        }
        nHeight = pindexPrev->height() + 1;
        pblock->height = nHeight;
        pblock->nTime = GetAdjustedTime();

        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();
        nLockTimeCutoff =
            (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : pblock->GetBlockTime();

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LOGA("CreateNewTailstormBlock: total size %llu txs: %llu of %llu fees: %lld sigops %u\n", nBlockSize, nBlockTx,
            mempool._size(), nFees, nBlockSigOps);

        // Populate vdag with subblocks and create coinbase tx
        std::map<uint256, CTransactionRef> allTxRefs;
        for (auto pDagNode : bestdag)
        {
            pblock->subblockNTxMap[pDagNode->subblock->GetHash()] = pDagNode->subblock->vtx.size();

            // account for all txs in all subblocks in dag
            for (auto txRef : pDagNode->subblock->vtx)
            {
                allTxRefs[txRef->GetHash()] = txRef;
            }
        }

        // Have to add coins to cache first since transactions are not necessarily in dependancy order
        for (auto &mi : allTxRefs)
        {
            const CTransaction &tx = *(mi.second);
            if (tx.IsProofBase())
                continue;

            try
            {
                AddCoins(cache, tx, nHeight);
            }
            catch (std::logic_error &e)
            {
                throw std::runtime_error(strprintf("repeated-tx: %s", tx.GetHash().ToString()));
            }
        }

        // insert unique txs (first index reserved for coinbase)  // TODO:  ptschip - add this in the loop above
        pblock->vtx.resize(allTxRefs.size() + 1);
        uint64_t idx = 1;
        for (auto &pair : allTxRefs)
        {
            pblock->vtx[idx] = pair.second;
            UpdateBlockStats(pair.second, cache);
            idx++;
        }
        pblock->vtx[0] = coinbaseTx(nHeight, nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus()), bestdag);
        UpdateBlockStats(pblock->vtx[0], cache);
        std::sort(pblock->vtx.begin() + 1, pblock->vtx.end(), TxEncodeHashComparator());

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
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        pblock->txCount = pblock->vtx.size();
        pblock->size = pblock->CalculateBlockSize();

        pblock->chainWork = ArithToUint256(pindexPrev->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->feePoolAmt = 0; // to be used later
        pblock->maxSize = 0; // to be used later
        pblock->hashAncestor.SetNull(); // to be used later
    }

    CValidationState state;

    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false))
    {
        throw std::runtime_error(
            strprintf("%s: TestTailstormBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    return pblocktemplate;
}

void TailstormBlockAssembler::UpdateBlockStats(CTransactionRef tx, CCoinsViewCache &cache)
{
    nBlockSize += tx->GetTxSize();
    ++nBlockTx;
    // nBlockSigOps += GetLegacySigOpCount(tx, STANDARD_SCRIPT_VERIFY_FLAGS);
    // TODO: ptschip - looks like all fees are just dumped into one big fee pool and shared
    //                 among subblocks...is that really the intent of tailstorm?
    CAmount nTxnFees = 0;
    CValidationState state;
    if (!tx->IsCoinBase())
        Consensus::CheckTxInputs(tx, state, cache, &nTxnFees);
    nFees += nTxnFees;
}
