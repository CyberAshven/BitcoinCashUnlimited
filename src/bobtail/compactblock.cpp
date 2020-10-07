// Copyright (c) 2016-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "blockrelay/blockrelay_common.h"
#include "bobtail/compactblock.h"
#include "bobtail/dag.h"
#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "connmgr.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "dosman.h"
#include "expedited.h"
#include "hashwrapper.h"
#include "main.h"
#include "net.h"
#include "parallel.h"
#include "policy/policy.h"
#include "pow.h"
#include "random.h"
#include "requestManager.h"
#include "streams.h"
#include "timedata.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "util.h"
#include "utiltime.h"
#include "validation/validation.h"

extern CCriticalSection cs_bobtailblocks;
extern std::map<uint256, CBobtailBlock> bobtailBlocks GUARDED_BY(cs_bobtailblocks);
extern CBobtailDagSet bobtailDagSet;

static bool BobReconstructBlock(CNode *pfrom,
    int &missingCount,
    int &unnecessaryCount,
    std::shared_ptr<CBlockThinRelay> pblock);


uint64_t BobGetShortID(const uint64_t &shorttxidk0, const uint64_t &shorttxidk1, const uint256 &txhash)
{
    static_assert(BobCompactBlock::SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}

#define MIN_TRANSACTION_SIZE (::GetSerializeSize(CTransaction(), SER_NETWORK, PROTOCOL_VERSION))

BobCompactBlock::BobCompactBlock(const CBobtailBlock &block)
    : nSize(0), nonce(GetRand(std::numeric_limits<uint64_t>::max())), nWaitingFor(0), coinbase(block.vtx[0]), header(block)
{
    FillShortTxIDSelector();

    for (auto subblock : block.vdag)
    {
        shorttxids.push_back(BobGetShortID(subblock->GetHash()));
    }
}

void BobCompactBlock::FillShortTxIDSelector() const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char *)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t BobCompactBlock::BobGetShortID(const uint256 &txhash) const
{
    return ::BobGetShortID(shorttxidk0, shorttxidk1, txhash);
}

void validateBobCompactBlock(std::shared_ptr<BobCompactBlock> bobcmpctblock)
{
    if (bobcmpctblock->header.IsNull() || bobcmpctblock->shorttxids.empty())
        throw std::invalid_argument("empty data in bobtail compact block");
}

/**
 * Handle an incoming compactblock.  The block is fully validated, and if any
 * transactions are missing we re-request them.
 */
bool BobCompactBlock::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    // Deserialize compactblock and store a block to reconstruct
    BobCompactBlock tmp;
    vRecv >> tmp;
    auto pblock = thinrelay.SetBlockToReconstruct(pfrom, tmp.header.GetHash());
    pblock->bobcmpctblock = std::make_shared<BobCompactBlock>(std::forward<BobCompactBlock>(tmp));

    std::shared_ptr<BobCompactBlock> compactBlock = pblock->bobcmpctblock;

    // Message consistency checking
    if (!IsBobCompactBlockValid(pfrom, compactBlock))
    {
        dosMan.Misbehaving(pfrom, 100);
        thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());
        return error("Received an invalid BobCompactBlock from peer %s\n", pfrom->GetLogName());
    }

    // Is there a previous block or header to connect with?
    CBlockIndex *pprev = LookupBlockIndex(compactBlock->header.hashPrevBlock);
    if (!pprev)
        return error("compact block from peer %s will not connect, unknown previous block %s", pfrom->GetLogName(),
            compactBlock->header.hashPrevBlock.ToString());

    CValidationState state;
    if (!ContextualCheckBlockHeader(compactBlock->header, state, pprev))
    {
        // compact block does not fit within our blockchain
        dosMan.Misbehaving(pfrom, 100);
        return error(
            "compact block from peer %s contextual error: %s", pfrom->GetLogName(), state.GetRejectReason().c_str());
    }

    CInv inv(MSG_BLOCK, compactBlock->header.GetHash());
    requester.UpdateBlockAvailability(pfrom->GetId(), inv.hash);
    LOG(CMPCT, "received compact block %s from peer %s of %d bytes\n", inv.hash.ToString(), pfrom->GetLogName(),
        compactBlock->GetSize());

    // Ban a node for sending unrequested compact blocks
    if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::BOBCMPCTBLOCK, inv.hash))
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("unrequested compact block from peer %s", pfrom->GetLogName());
    }

    // Check if we've already received this block and have it on disk
    if (AlreadyHaveBlock(inv))
    {
        requester.AlreadyReceived(pfrom, inv);
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        LOG(CMPCT, "Received BobCompactBlock but returning because we already have this block %s on disk, peer=%s\n",
            inv.hash.ToString(), pfrom->GetLogName());
        return true;
    }

    return compactBlock->process(pfrom, pblock);
}


bool BobCompactBlock::process(CNode *pfrom, std::shared_ptr<CBlockThinRelay> pblock)
{
    pblock->nVersion = header.nVersion;
    pblock->nBits = header.nBits;
    pblock->nNonce = header.nNonce;
    pblock->nTime = header.nTime;
    pblock->hashMerkleRoot = header.hashMerkleRoot;
    pblock->hashPrevBlock = header.hashPrevBlock;

    // Store the salt used by this peer.
    pfrom->shorttxidk0.store(shorttxidk0);
    pfrom->shorttxidk1.store(shorttxidk1);

    DbgAssert(pblock->bobcmpctblock != nullptr, return false);
    DbgAssert(pblock->bobcmpctblock.get() == this, return false);
    std::shared_ptr<BobCompactBlock> bobcmpctblock = pblock->bobcmpctblock;

    bobcmpctblock->vSubHashes = shorttxids;
    bobcmpctblock->coinbase = coinbase;

    // Create a map of all short tx hashes pointing to their full tx hash counterpart
    // We need to check all transaction sources (orphan list, mempool, and new (incoming) transactions in this block)
    int missingCount = 0;
    int unnecessaryCount = 0;
    std::map<uint64_t, uint256> mapPartialTxHash;
    std::vector<uint256> memPoolHashes;
    std::set<uint64_t> setHashesToRequest;
    unsigned int nWaitingForTxns = bobcmpctblock->nWaitingFor;

    bool fMerkleRootCorrect = true;
    uint256 merkleroot;
    {
        for (auto kv : bobtailDagSet.mapAllNodes)
        {
            CSubBlock subblock = kv.second.subblock;
            uint64_t cheapHash = BobGetShortID(subblock.GetHash());
            mapPartialTxHash[cheapHash] = subblock.GetHash();
        }

        // Start gathering the full subblock hashes. If some are not available then add them to setHashesToRequest.
        for (const uint64_t &cheapHash : pblock->bobcmpctblock->vSubHashes)
        {
            if (mapPartialTxHash.find(cheapHash) != mapPartialTxHash.end())
            {
                pblock->bobcmpctblock->vSubHashes256.push_back(mapPartialTxHash[cheapHash]);
            }
            else
            {
                setHashesToRequest.insert(cheapHash);

                // If there are more hashes to request than available indices then we will not be able to
                // reconstruct the compact block so just send a full block.
                if (setHashesToRequest.size() > std::numeric_limits<uint16_t>::max())
                {
                    // Since we can't process this BobCompactBlock then clear out the data from memory
                    thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());

                    thinrelay.RequestBlock(pfrom, header.GetHash());
                    return error("Too many re-requested hashes for BobCompactBlock: requesting a full block");
                }
            }
        }

        // We don't need this after here.
        mapPartialTxHash.clear();

        // Reconstruct the block if there are no hashes to re-request
        if (setHashesToRequest.empty())
        {
            if (!BobReconstructBlock(pfrom, missingCount, unnecessaryCount, pblock))
            {
                return false;
            }
            merkleroot = BlockMerkleRoot((CBlock)(*pblock));
            if (header.hashMerkleRoot != merkleroot)
            {
                fMerkleRootCorrect = false;
            }
        }
    } // End locking orphanpool.cs, mempool.cs
    LOG(CMPCT, "Current in memory BobCompactBlock size is %ld bytes\n", pblock->nCurrentBlockSize);

    // These must be checked outside of the mempool.cs lock or deadlock may occur.
    // A merkle root mismatch here does not cause a ban because and expedited node will forward an xthin
    // without checking the merkle root, therefore we don't want to ban our expedited nodes. Just re-request
    // a full block if a mismatch occurs.
    if (!fMerkleRootCorrect)
    {
        return error("mismatched merkle root on BobCompactBlock %s vs %s: rerequesting a full block, peer=%s", 
                header.hashMerkleRoot.ToString(), merkleroot.ToString(), pfrom->GetLogName());

        thinrelay.ClearAllBlockData(pfrom, header.GetHash());
        thinrelay.RequestBlock(pfrom, header.GetHash());
        return true;
    }

    nWaitingForTxns = missingCount;
    LOG(CMPCT, "BobCompactBlock waiting for: %d, unnecessary: %d, total txns: %d received txns: %d\n", nWaitingForTxns,
        unnecessaryCount, pblock->vtx.size(), bobcmpctblock->mapMissingTx.size());

    // If there are any missing hashes or transactions then we request them here.
    // This must be done outside of the mempool.cs lock or may deadlock.
    if (setHashesToRequest.size() > 0)
    {
        nWaitingForTxns = setHashesToRequest.size();
        BobCompactReRequest compactReRequest;
        compactReRequest.blockhash = header.GetHash();
        compactReRequest.subBlockHashes = setHashesToRequest;
        compactReRequest.shorttxidk0 = bobcmpctblock->shorttxidk0;
        compactReRequest.shorttxidk1 = bobcmpctblock->shorttxidk1;
        pfrom->PushMessage(NetMsgType::GETBOBSUB, compactReRequest);

        // Update run-time statistics of compact block bandwidth savings
        bobcompactdata.UpdateInBoundReRequestedTx(nWaitingForTxns);
        return true;
    }

    // If there are still any missing transactions then we must clear out the compactblock data
    // and re-request a full block (This should never happen because we just checked the various pools).
    if (missingCount > 0)
    {
        // Since we can't process this compactblock then clear out the data from memory
        thinrelay.ClearAllBlockData(pfrom, header.GetHash());

        thinrelay.RequestBlock(pfrom, header.GetHash());
        return error("Still missing transactions for BobCompactBlock: re-requesting a full block");
    }

    // We now have all the transactions now that are in this block
    int blockSize = pblock->GetBlockSize();
    LOG(CMPCT, "Reassembled BobCompactBlock for %s (%d bytes). Message was %d bytes, compression ratio %3.2f, peer=%s\n",
        pblock->GetHash().ToString(), blockSize, bobcmpctblock->GetSize(),
        ((float)blockSize) / ((float)bobcmpctblock->GetSize()), pfrom->GetLogName());

    // Update run-time statistics of compact block bandwidth savings
    bobcompactdata.UpdateInBound(bobcmpctblock->GetSize(), blockSize);
    LOG(CMPCT, "compact block stats: %s\n", bobcompactdata.ToString());

    // Process the full block
    PV->HandleBlockMessage(pfrom, NetMsgType::CMPCTBLOCK, pblock, GetInv());

    return true;
}

bool BobCompactReRequest::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    BobCompactReRequest compactReRequest;
    vRecv >> compactReRequest;
    // Message consistency checking
    if (compactReRequest.subBlockHashes.empty() || compactReRequest.blockhash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("incorrectly constructed BobCompactReRequest received.  Banning peer=%s", pfrom->GetLogName());
    }

    // We use MSG_TX here even though we refer to blockhash because we need to track
    // how many xblocktx requests we make in case of DOS
    CInv inv(MSG_TX, compactReRequest.blockhash);
    LOG(CMPCT, "received BobCompactReRequest for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());

    CBobtailBlock block;
    {
        LOCK(cs_bobtailblocks);

        if (bobtailBlocks.count(inv.hash) > 0)
        {
            block = bobtailBlocks[inv.hash];
        }
        else
        {
            dosMan.Misbehaving(pfrom, 20);
            return error("Required bobtail block is not available");
        }
    }

    BobCompactReReqResponse compactReqResponse(block, compactReRequest.subBlockHashes, compactReRequest.shorttxidk0, compactReRequest.shorttxidk1);
    pfrom->PushMessage(NetMsgType::BOBSUB, compactReqResponse);   //TODO: Needs new message type
    pfrom->txsSent += compactReRequest.subBlockHashes.size();       //TODO: updating wrong statistic here; add subblock ct?

    return true;
}

bool BobCompactReReqResponse::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    std::string strCommand = NetMsgType::BOBSUB;
    size_t msgSize = vRecv.size();
    BobCompactReReqResponse compactReReqResponse;
    vRecv >> compactReReqResponse;

    // Message consistency checking
    CInv inv(MSG_BOB_CMPCT_BLOCK, compactReReqResponse.blockhash);
    if (compactReReqResponse.subBlocks.empty() || compactReReqResponse.blockhash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error(
            "incorrectly constructed BobCompactReReqResponse or inconsistent BobCompactBlock data received.  Banning peer=%s",
            pfrom->GetLogName());
    }
    LOG(CMPCT, "received BobCompactReReqResponse for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());
    {
        // Do not process unrequested xblocktx unless from an expedited node.
        if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::BOBCMPCTBLOCK, inv.hash) && !connmgr->IsExpeditedUpstream(pfrom))
        {
            dosMan.Misbehaving(pfrom, 10);
            return error("Received BobCompactReReqResponse %s from peer %s but was unrequested", inv.hash.ToString(),
                pfrom->GetLogName());
        }
    }

    auto pblock = thinrelay.GetBlockToReconstruct(pfrom, compactReReqResponse.blockhash);
    if (pblock == nullptr)
        return error("No block available to reconstruct for bobsub");
    std::shared_ptr<BobCompactBlock> bobcmpctblock = pblock->bobcmpctblock;

    // Check if we've already received this block and have it on disk
    if (AlreadyHaveBlock(inv))
    {
        requester.AlreadyReceived(pfrom, inv);
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        LOG(CMPCT,
            "Received BobCompactReReqResponse but returning because we already have this block %s on disk, peer=%s\n",
            inv.hash.ToString(), pfrom->GetLogName());
        return true;
    }

    // Subblocks needed
    int subNeeded = bobcmpctblock->vSubHashes.size() - bobcmpctblock->vSubHashes256.size();

    // Update compact bobtail block and insert subblocks into dag
    for (auto subblock : compactReReqResponse.subBlocks)
    {
        bobcmpctblock->vSubHashes256.push_back(subblock.GetHash());
        bobtailDagSet.Insert(subblock);
    }

    LOG(CMPCT, "Got %d Re-requested subblocks, needed %d of them from peer=%s\n", compactReReqResponse.subBlocks.size(), subNeeded,
        pfrom->GetLogName());

    int missingCount = 0;
    int unnecessaryCount = 0;
    // Look for each transaction in our various pools and buffers.
    // With compactblocks the vSubHashes contains only the first 6 bytes of the tx hash.
    {
        if (!BobReconstructBlock(pfrom, missingCount, unnecessaryCount, pblock))
            return false;
    }

    std::vector<uint256> vTxHashes256;
    for (auto &tx : pblock->vtx)
    {
        vTxHashes256.push_back(tx->GetHash());
    }
    std::sort(vTxHashes256.begin() + 1, vTxHashes256.end());

    // At this point we should have all the full hashes in the block. Check that the merkle
    // root in the block header matches the merkleroot calculated from the hashes provided.
    uint256 merkleroot = BlockMerkleRoot((CBlock)(*pblock));
    if (pblock->hashMerkleRoot != merkleroot)
    {
        thinrelay.ClearAllBlockData(pfrom, inv.hash);
        return error("Merkle root for %s does not match computed merkle root, peer=%s", inv.hash.ToString(),
            pfrom->GetLogName());
    }
    LOG(CMPCT, "Merkle Root check passed for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());

    // If we're still missing transactions then bail out and just request the full block. This should never
    // happen unless we're under some kind of attack or somehow we lost transactions out of our memory pool
    // while we were retreiving missing transactions.
    if (missingCount > 0)
    {
        // Since we can't process this compactblock then clear out the data from memory
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        thinrelay.RequestBlock(pfrom, inv.hash);
        return error("Still missing transactions after reconstructing block, peer=%s: re-requesting a full block",
            pfrom->GetLogName());
    }
    else
    {
        // We have all the transactions now that are in this block: try to reassemble and process.
        CInv inv2(CInv(MSG_BLOCK, compactReReqResponse.blockhash));

        // for compression statistics, we have to add up the size of compactblock and the re-requested Txns.
        uint64_t nSizeCompactBlockTx = msgSize;
        uint64_t nBlockSize = pblock->GetBlockSize();
        uint64_t nCmpctBlkSize = bobcmpctblock->GetSize();
        LOG(CMPCT,
            "Reassembled BobCompactReReqResponse for %s (%d bytes). Message was %d bytes (compactblock) and %d bytes "
            "(re-requested tx), compression ratio %3.2f, peer=%s\n",
            pblock->GetHash().ToString(), nBlockSize, nCmpctBlkSize, nSizeCompactBlockTx,
            ((float)nBlockSize) / ((float)nCmpctBlkSize + (float)nSizeCompactBlockTx), pfrom->GetLogName());

        // Update run-time statistics of compactblock bandwidth savings.
        // We add the original compactblock size with the size of transactions that were re-requested.
        // This is NOT double counting since we never accounted for the original compactblock due to the re-request.
        bobcompactdata.UpdateInBound(nSizeCompactBlockTx + nCmpctBlkSize, nBlockSize);
        LOG(CMPCT, "BobCompactBlock stats: %s\n", bobcompactdata.ToString());

        PV->HandleBlockMessage(pfrom, strCommand, pblock, inv2);
    }

    return true;
}

static bool BobReconstructBlock(CNode *pfrom,
    int &missingCount,
    int &unnecessaryCount,
    std::shared_ptr<CBlockThinRelay> pblock)
{
    // We must have all the full tx hashes by this point.  We first check for any duplicate
    // transaction ids.  This is a possible attack vector and has been used in the past.
    {
        std::set<uint256> setHashes(pblock->bobcmpctblock->vSubHashes256.begin(), pblock->bobcmpctblock->vSubHashes256.end());
        if (setHashes.size() != pblock->bobcmpctblock->vSubHashes256.size())
        {
            thinrelay.ClearAllBlockData(pfrom, pblock->GetHash());
            return error("Duplicate subblock ids, peer=%s", pfrom->GetLogName());
        }
    }

    // Add the header size to the current size being tracked
    thinrelay.AddBlockBytes(::GetSerializeSize(pblock->GetBlockHeader(), SER_NETWORK, PROTOCOL_VERSION), pblock);

    // Look for each transaction in our various pools and buffers.
    // With compactblocks the vSubHashes contains only the first 6 bytes of the tx hash.
    for (const uint256 &hash : pblock->bobcmpctblock->vSubHashes256)
    {
        CSubBlock subblock;
        bool found = bobtailDagSet.Find(hash, subblock);

        if (!found)
            return false;

        thinrelay.AddBlockBytes(0, pblock); //TODO: actually add subblock bytes
        //TODO: Check for memory exhaustion attack

        // Add this transaction. If the tx is null we still add it as a placeholder to keep the correct
        // ordering.
        pblock->vdag.push_back(std::make_shared<CSubBlock>(subblock));
    }

    // TODO: Perhaps there is a better way to get the tx list?
    CBobtailBlock bobblock;
    bobblock.vdag = pblock->vdag;
    bobblock.UpdateTxLists();
    pblock->vtx = bobblock.vtx;
    pblock->vtx[0] = pblock->bobcmpctblock->coinbase;

    // Now that we've rebuilt the block successfully we can set the XVal flag which is used in
    // ConnectBlock() to determine which if any inputs we can skip the checking of inputs.
    pblock->fXVal = true;

    return true;
}


template <class T>
void CBobCompactBlockData::expireStats(std::map<int64_t, T> &statsMap)
{
    AssertLockHeld(cs_compactblockstats);
    // Delete any entries that are more than 24 hours old
    int64_t nTimeCutoff = getTimeForStats() - 60 * 60 * 24 * 1000;

    typename std::map<int64_t, T>::iterator iter = statsMap.begin();
    while (iter != statsMap.end())
    {
        // increment to avoid iterator becoming invalid when erasing below
        typename std::map<int64_t, T>::iterator mi = iter++;

        if (mi->first < nTimeCutoff)
            statsMap.erase(mi);
    }
}

template <class T>
void CBobCompactBlockData::updateStats(std::map<int64_t, T> &statsMap, T value)
{
    AssertLockHeld(cs_compactblockstats);
    statsMap[getTimeForStats()] = value;
    expireStats(statsMap);
}


//  Calculate average of values in map. Return 0 for no entries.
// Expires values before calculation.
double CBobCompactBlockData::average(std::map<int64_t, uint64_t> &map)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(map);

    if (map.size() == 0)
        return 0.0;

    uint64_t accum = 0U;
    for (std::pair<int64_t, uint64_t> const &ref : map)
    {
        // avoid wraparounds
        accum = std::max(accum, accum + ref.second);
    }
    return (double)accum / map.size();
}

double CBobCompactBlockData::computeTotalBandwidthSavingsInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);

    return double(nOriginalSize() - nCompactSize());
}

double CBobCompactBlockData::compute24hAverageCompressionInternal(
    std::map<int64_t, std::pair<uint64_t, uint64_t> > &mapCompactBlocks) EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(mapCompactBlocks);

    double nCompressionRate = 0;
    uint64_t nCompactSizeTotal = 0;
    uint64_t nOriginalSizeTotal = 0;
    for (const auto &mi : mapCompactBlocks)
    {
        nCompactSizeTotal += mi.second.first;
        nOriginalSizeTotal += mi.second.second;
    }

    if (nOriginalSizeTotal > 0)
        nCompressionRate = 100 - (100 * (double)(nCompactSizeTotal) / nOriginalSizeTotal);

    return nCompressionRate;
}

double CBobCompactBlockData::compute24hInboundRerequestTxPercentInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats)
{
    AssertLockHeld(cs_compactblockstats);

    expireStats(mapCompactBlocksInBoundReRequestedTx);
    expireStats(mapCompactBlocksInBound);

    double nReRequestRate = 0;
    uint64_t nTotalReRequests = 0;
    uint64_t nTotalReRequestedTxs = 0;
    for (const auto &mi : mapCompactBlocksInBoundReRequestedTx)
    {
        nTotalReRequests += 1;
        nTotalReRequestedTxs += mi.second;
    }

    if (mapCompactBlocksInBound.size() > 0)
        nReRequestRate = 100 * (double)nTotalReRequests / mapCompactBlocksInBound.size();

    return nReRequestRate;
}

void CBobCompactBlockData::UpdateInBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_compactblockstats);
    // Update InBound compactblock tracking information
    nOriginalSize += nOriginalBlockSize;
    nCompactSize += nCompactBlockSize;
    nInBoundBlocks += 1;
    updateStats(mapCompactBlocksInBound, std::pair<uint64_t, uint64_t>(nCompactBlockSize, nOriginalBlockSize));
}

void CBobCompactBlockData::UpdateOutBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_compactblockstats);
    nOriginalSize += nOriginalBlockSize;
    nCompactSize += nCompactBlockSize;
    nOutBoundBlocks += 1;
    updateStats(mapCompactBlocksOutBound, std::pair<uint64_t, uint64_t>(nCompactBlockSize, nOriginalBlockSize));
}

void CBobCompactBlockData::UpdateResponseTime(double nResponseTime)
{
    LOCK(cs_compactblockstats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && IsBobCompactBlocksEnabled())
    {
        updateStats(mapCompactBlockResponseTime, nResponseTime);
    }
}

void CBobCompactBlockData::UpdateValidationTime(double nValidationTime)
{
    LOCK(cs_compactblockstats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && IsBobCompactBlocksEnabled())
    {
        updateStats(mapCompactBlockValidationTime, nValidationTime);
    }
}

void CBobCompactBlockData::UpdateInBoundReRequestedTx(int nReRequestedTx)
{
    LOCK(cs_compactblockstats);

    // Update InBound compactblock tracking information
    updateStats(mapCompactBlocksInBoundReRequestedTx, nReRequestedTx);
}

void CBobCompactBlockData::UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved)
{
    LOCK(cs_compactblockstats);
    nMempoolLimiterBytesSaved += nBytesSaved;
}

void CBobCompactBlockData::UpdateCompactBlock(uint64_t nCompactBlockSize)
{
    LOCK(cs_compactblockstats);
    nTotalCompactBlockBytes += nCompactBlockSize;
    updateStats(mapCompactBlock, nCompactBlockSize);
}

void CBobCompactBlockData::UpdateFullTx(uint64_t nFullTxSize)
{
    LOCK(cs_compactblockstats);
    nTotalCompactBlockBytes += nFullTxSize;
    updateStats(mapFullTx, nFullTxSize);
}

std::string CBobCompactBlockData::ToString()
{
    LOCK(cs_compactblockstats);
    double size = computeTotalBandwidthSavingsInternal();
    std::ostringstream ss;
    ss << nInBoundBlocks() << " inbound and " << nOutBoundBlocks() << " outbound BobCompactBlocks have saved "
       << formatInfoUnit(size) << " of bandwidth";
    return ss.str();
}

// Calculate the percentage compression over the last 24 hours for inbound blocks
std::string CBobCompactBlockData::InBoundPercentToString()
{
    LOCK(cs_compactblockstats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapCompactBlocksInBound);

    // NOTE: Potential gotcha, compute24hAverageCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksInBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapCompactBlocksInBound.size()
       << " Inbound  BobCompactBlocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the percentage compression over the last 24 hours for outbound blocks
std::string CBobCompactBlockData::OutBoundPercentToString()
{
    LOCK(cs_compactblockstats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapCompactBlocksOutBound);

    // NOTE: Potential gotcha, compute24hAverageCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksOutBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapCompactBlocksOutBound.size()
       << " Outbound BobCompactBlocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the average response time over the last 24 hours
std::string CBobCompactBlockData::ResponseTimeToString()
{
    LOCK(cs_compactblockstats);

    expireStats(mapCompactBlockResponseTime);

    std::vector<double> vResponseTime;

    double nResponseTimeAverage = 0;
    double nPercentile = 0;
    double nTotalResponseTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapCompactBlockResponseTime)
    {
        nTotalEntries += 1;
        nTotalResponseTime += mi.second;
        vResponseTime.push_back(mi.second);
    }

    if (nTotalEntries > 0)
    {
        nResponseTimeAverage = (double)nTotalResponseTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vResponseTime.begin(), vResponseTime.end());
        nPercentile = vResponseTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Response time   (last 24hrs) AVG:" << nResponseTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the average validation time over the last 24 hours
std::string CBobCompactBlockData::ValidationTimeToString()
{
    LOCK(cs_compactblockstats);

    expireStats(mapCompactBlockValidationTime);

    std::vector<double> vValidationTime;

    double nValidationTimeAverage = 0;
    double nPercentile = 0;
    double nTotalValidationTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapCompactBlockValidationTime)
    {
        nTotalEntries += 1;
        nTotalValidationTime += mi.second;
        vValidationTime.push_back(mi.second);
    }

    if (nTotalEntries > 0)
    {
        nValidationTimeAverage = (double)nTotalValidationTime / nTotalEntries;

        // Calculate the 95th percentile
        uint64_t nPercentileElement = static_cast<int>((nTotalEntries * 0.95) + 0.5) - 1;
        sort(vValidationTime.begin(), vValidationTime.end());
        nPercentile = vValidationTime[nPercentileElement];
    }

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "Validation time (last 24hrs) AVG:" << nValidationTimeAverage << ", 95th pcntl:" << nPercentile;
    return ss.str();
}

// Calculate the transaction re-request ratio and counter over the last 24 hours
std::string CBobCompactBlockData::ReRequestedTxToString()
{
    LOCK(cs_compactblockstats);

    double nReRequestRate = compute24hInboundRerequestTxPercentInternal();

    // NOTE: Potential gotcha, compute24hInboundRerequestTxPercentInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapCompactBlocksInBoundReRequestedTx
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Tx re-request rate (last 24hrs): " << nReRequestRate
       << "% Total re-requests:" << mapCompactBlocksInBoundReRequestedTx.size();
    return ss.str();
}

std::string CBobCompactBlockData::MempoolLimiterBytesSavedToString()
{
    LOCK(cs_compactblockstats);
    double size = (double)nMempoolLimiterBytesSaved();
    std::ostringstream ss;
    ss << "BobCompactBlock mempool limiting has saved " << formatInfoUnit(size) << " of bandwidth";
    return ss.str();
}

// Calculate the average compact block size
std::string CBobCompactBlockData::CompactBlockToString()
{
    LOCK(cs_compactblockstats);
    double avgCompactBlockSize = average(mapCompactBlock);
    std::ostringstream ss;
    ss << "BobCompactBlock size (last 24hrs) AVG: " << formatInfoUnit(avgCompactBlockSize);
    return ss.str();
}

// Calculate the average size of all full txs sent with block
std::string CBobCompactBlockData::FullTxToString()
{
    LOCK(cs_compactblockstats);
    double avgFullTxSize = average(mapFullTx);
    std::ostringstream ss;
    ss << "compactblock full transactions size (last 24hrs) AVG: " << formatInfoUnit(avgFullTxSize);
    return ss.str();
}

void CBobCompactBlockData::ClearCompactBlockStats()
{
    LOCK(cs_compactblockstats);

    nOriginalSize.Clear();
    nCompactSize.Clear();
    nInBoundBlocks.Clear();
    nOutBoundBlocks.Clear();
    nMempoolLimiterBytesSaved.Clear();
    nTotalCompactBlockBytes.Clear();
    nTotalFullTxBytes.Clear();

    mapCompactBlocksInBound.clear();
    mapCompactBlocksOutBound.clear();
    mapCompactBlockResponseTime.clear();
    mapCompactBlockValidationTime.clear();
    mapCompactBlocksInBoundReRequestedTx.clear();
    mapCompactBlock.clear();
    mapFullTx.clear();
}

void CBobCompactBlockData::FillCompactBlockQuickStats(BobCompactBlockQuickStats &stats)
{
    if (!IsBobCompactBlocksEnabled())
        return;

    LOCK(cs_compactblockstats);

    stats.nTotalInbound = nInBoundBlocks();
    stats.nTotalOutbound = nOutBoundBlocks();
    stats.nTotalBandwidthSavings = computeTotalBandwidthSavingsInternal();

    // NOTE: The following calls rely on the side-effect of the compute*Internal
    //       calls also calling expireStats on the associated statistics maps
    //       This is why we set the % value first, then the count second for compression values
    stats.fLast24hInboundCompression = compute24hAverageCompressionInternal(mapCompactBlocksInBound);
    stats.nLast24hInbound = mapCompactBlocksInBound.size();
    stats.fLast24hOutboundCompression = compute24hAverageCompressionInternal(mapCompactBlocksOutBound);
    stats.nLast24hOutbound = mapCompactBlocksOutBound.size();
    stats.fLast24hRerequestTxPercent = compute24hInboundRerequestTxPercentInternal();
    stats.nLast24hRerequestTx = mapCompactBlocksInBoundReRequestedTx.size();
}

bool IsBobCompactBlocksEnabled() { return GetBoolArg("-use-BobCompactBlocks", true); }
void BobSendCompactBlock(const CBobtailBlockRef pblock, CNode *pfrom, const CInv &inv)
{
    if (inv.type == MSG_BOB_CMPCT_BLOCK)
    {
        BobCompactBlock compactBlock;
        {
            LOCK(pfrom->cs_inventory);
            compactBlock = BobCompactBlock(*pblock);
        }
        uint64_t nSizeBlock = pblock->GetBlockSize();

        // Send a compact block
        if (compactBlock.GetSize() < nSizeBlock)
        {
            bobcompactdata.UpdateOutBound(compactBlock.GetSize(), nSizeBlock);
            pfrom->PushMessage(NetMsgType::BOBCMPCTBLOCK, compactBlock);
            LOG(CMPCT, "Sent compact block - BobCompactBlock size: %d vs block size: %d peer: %s\n",
                compactBlock.GetSize(), nSizeBlock, pfrom->GetLogName());

            bobcompactdata.UpdateCompactBlock(compactBlock.GetSize());
            bobcompactdata.UpdateFullTx(0); //TODO: Remove FullTx from stats
            pfrom->blocksSent += 1;
        }
        else // send full block
        {
            pfrom->PushMessage(NetMsgType::BLOCK, *pblock);
            LOG(CMPCT, "Sent regular block instead - BobCompactBlock size: %d vs block size: %d , peer: %s\n",
                compactBlock.GetSize(), nSizeBlock, pfrom->GetLogName());
        }
    }
}

bool IsBobCompactBlockValid(CNode *pfrom, std::shared_ptr<BobCompactBlock> compactBlock)
{
    validateBobCompactBlock(compactBlock);

    // Check that we havn't exceeded the max allowable block size that would be reconstructed from this
    // set of hashes
    uint64_t nTxnsInBlock = compactBlock->shorttxids.size();
    if (nTxnsInBlock > (thinrelay.GetMaxAllowedBlockSize() / MIN_TX_SIZE))
        return error("Number of hashes in BobCompactBlock would reconstruct a block greather than the block size limit\n");

    // check block header
    CValidationState state;
    if (!CheckBlockHeader(compactBlock->header, state, true))
    {
        return error("Received invalid header for BobCompactBlock %s from peer %s",
            compactBlock->header.GetHash().ToString(), pfrom->GetLogName());
    }
    if (state.Invalid())
    {
        return error("Received invalid header for BobCompactBlock %s from peer %s",
            compactBlock->header.GetHash().ToString(), pfrom->GetLogName());
    }

    return true;
}
