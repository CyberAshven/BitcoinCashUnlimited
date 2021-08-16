// Copyright (c) 2018-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "graphene.h"
#include "tailstorm/blockrelay/graphenerelay.h"
#include "tailstorm/dag.h"
#include "tailstorm/subblock/validation.h"

// other bitcoin includes
#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "connmgr.h"
#include "consensus/merkle.h"
#include "dosman.h"
#include "expedited.h"
#include "extversionkeys.h"
#include "net.h"
#include "policy/policy.h"
#include "pow.h"
#include "requestManager.h"
#include "timedata.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "util.h"
#include "utiltime.h"
#include "validation/validation.h"

#include <iomanip>
extern CTweak<uint64_t> grapheneMinVersionSupported;
extern CTweak<uint64_t> grapheneMaxVersionSupported;
extern CTweak<uint64_t> grapheneFastFilterCompatibility;
extern CTailstormDagSet tailstormDagSet;

bool ReconstructBlock(CNode *pfrom, CSBGrapheneBlock* grapheneBlock, const std::map<uint64_t, CTransactionRef> &mapTxFromPools)
{
    // We must have all the full tx hashes by this point.  We first check for any repeating
    // sequences in transaction id's.  This is a possible attack vector and has been used in the past.
    {
        std::set<uint256> setHashes(grapheneBlock->vTxHashes256.begin(), grapheneBlock->vTxHashes256.end());
        if (setHashes.size() != grapheneBlock->vTxHashes256.size())
        {
            thinrelay.ClearAllBlockData(pfrom, grapheneBlock->GetHash());
            return error("Repeating Transaction Id sequence, peer=%s", pfrom->GetLogName());
        }
    }

    // Add the header size to the current size being tracked
    grapheneBlock->nCurrentBlockSize += (::GetSerializeSize(grapheneBlock->GetBlockHeader(), SER_NETWORK, PROTOCOL_VERSION));

    // If we have incomplete infomation about this block, resize the block transaction count to accomodate new data
    if (grapheneBlock->vtx.size() < grapheneBlock->vTxHashes256.size())
    {
        grapheneBlock->vtx.resize(grapheneBlock->vTxHashes256.size());
    }

    // Collect hashes of txs that will need to be verified
    std::set<uint256> toVerify;
    {
        READLOCK(orphanpool.cs_orphanpool);
        for (auto &kv : orphanpool.mapOrphanTransactions)
        {
            toVerify.insert(kv.first);
        }
    }
    for (auto &tx : grapheneBlock->vAdditionalTxs)
    {
        toVerify.insert(tx->GetHash());
    }
    for (auto &tx : grapheneBlock->vRecoveredTxs)
    {
        toVerify.insert(tx->GetHash());
    }
    for (auto &kv : grapheneBlock->mapMissingTx)
    {
        toVerify.insert(kv.second->GetHash());
    }

    // Locate each transaction in pre-populated mapTxFromPools.
    int idx = -1;
    CTransactionRef ptx = nullptr;
    for (const uint256 &hash : grapheneBlock->vTxHashes256)
    {
        idx++;
        uint64_t nShortId = SBGetShortID(
            pfrom->gr_shorttxidk0.load(), pfrom->gr_shorttxidk1.load(), hash, SBNegotiateGrapheneVersion(pfrom));
        const auto iter = mapTxFromPools.find(nShortId);

        if ((iter != mapTxFromPools.end()) && (iter->second != nullptr))
        {
            ptx = iter->second;
            grapheneBlock->vtx[idx] = ptx;
        }
        else
        {
            thinrelay.ClearAllBlockData(pfrom, grapheneBlock->GetHash());
            return error("Malformed mapTxFromPools, null transaction reference found, peer=%s", pfrom->GetLogName());
        }

        // XVal: these transactions still need to be verified since they were not in the mempool
        // or CommitQ.
        if (toVerify.count(hash) > 0)
        {
            grapheneBlock->setUnVerifiedTxns.insert(hash);
        }

        // In order to prevent a memory exhaustion attack we track transaction bytes used to recreate the block
        // in order to see if we've exceeded any limits and if so clear out data and return.
        grapheneBlock->nCurrentBlockSize += ptx->GetTxSize();
        if (grapheneBlock->nCurrentBlockSize > thinrelay.GetMaxAllowedBlockSize())
        {
            uint64_t nBlockBytes = grapheneBlock->nCurrentBlockSize;
            thinrelay.ClearAllBlockData(pfrom, grapheneBlock->GetHash());
            pfrom->fDisconnect = true;
            return error(
                "Reconstructed block %s (size:%llu) has caused max memory limit %llu bytes to be exceeded, peer=%s",
                grapheneBlock->GetHash().ToString(), nBlockBytes, thinrelay.GetMaxAllowedBlockSize(), pfrom->GetLogName());
        }
    }
    return true;
}

/* SubBlock methods
 */
void CSBGrapheneBlock::SetNull()
{
    nCurrentBlockSize = 0;
    nSize = 0;
    nWaitingFor = 0;
    vTxHashes256.clear();
    mapMissingTx.clear();
    vAdditionalTxs.clear();
    vRecoveredTxs.clear();
    mapHashOrderIndex.clear();
    shorttxidk0 = 0;
    shorttxidk1 = 0;
    nVersion = 0;
    hashPrevBlock.SetNull();
    hashMerkleRoot.SetNull();
    nTime = 0;
    nBits = 0;
    nNonce = 0;
    vtx.clear();
    nBlockTxs = 0;
    pGrapheneSet = nullptr;
}

bool CSBGrapheneBlock::IsNull() const
{
    return (nBlockTxs == 0 && nBits == 0);
}

std::string CSBGrapheneBlock::ToString() const
{
    std::stringstream s;
    s << strprintf(
        "CGrapheneBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nBlockTxs);
    for (unsigned int i = 0; i < vTxHashes256.size(); i++)
    {
        s << "  " << vTxHashes256[i].GetHex() << "\n";
    }
    return s.str();
}

std::set<uint256> CSBGrapheneBlock::GetAncestorHashes() const
{
    std::set<uint256> ancestors;
    if (vAdditionalTxs.empty())
    {
        return ancestors;
    }
    if (vAdditionalTxs[0]->IsProofBase() == false)
    {
        return ancestors;
    }
    for (auto &input : vAdditionalTxs[0]->vin)
    {
        ancestors.emplace(input.prevout.hash);
    }
    return ancestors;
}

std::vector<uint256> CSBGrapheneBlock::GetTxHashes() const
{
    return vTxHashes256;
}

/* CMempoolInfo methods
 */

CSBMemPoolInfo::CSBMemPoolInfo(uint64_t _nTx) : nTx(_nTx) {}
CSBMemPoolInfo::CSBMemPoolInfo() { this->nTx = 0; }
CSBGrapheneBlock::CSBGrapheneBlock(const CSubBlockRef pblock,
    uint64_t nReceiverMemPoolTx,
    uint64_t nSenderMempoolPlusBlock,
    uint64_t _version,
    bool _computeOptimized)
    : // Use cryptographically strong pseudorandom number because
      // we will extract SipHash secret key from this
      sipHashNonce(GetRand(std::numeric_limits<uint64_t>::max())),
      nSize(0), nWaitingFor(0), shorttxidk0(0), shorttxidk1(0), version(_version), computeOptimized(_computeOptimized)
{
    SetNull();
    *((CSubBlock *)this) = *pblock;
    nBlockTxs = pblock->vtx.size();
    uint64_t grapheneSetVersion = CSBGrapheneBlock::GetGrapheneSetVersion(version);

    if (version >= 2)
        FillShortTxIDSelector();

    std::vector<uint256> blockHashes;
    for (const auto &tx : pblock->vtx)
    {
        blockHashes.push_back(tx->GetHash());

        if (tx->IsProofBase())
            vAdditionalTxs.push_back(tx);
    }

    if (fCanonicalTxsOrder)
        pGrapheneSet =
            std::make_shared<CGrapheneSet>(CGrapheneSet(nReceiverMemPoolTx, nSenderMempoolPlusBlock, blockHashes,
                shorttxidk0, shorttxidk1, grapheneSetVersion, (uint32_t)sipHashNonce, computeOptimized, false));
    else
        pGrapheneSet = std::make_shared<CGrapheneSet>(CGrapheneSet(nReceiverMemPoolTx, nSenderMempoolPlusBlock,
            blockHashes, shorttxidk0, shorttxidk1, grapheneSetVersion, (uint32_t)sipHashNonce, computeOptimized, true));
}

CSBGrapheneBlock::CSBGrapheneBlock(const CSubBlock &pblock,
    uint64_t nReceiverMemPoolTx,
    uint64_t nSenderMempoolPlusBlock,
    uint64_t _version,
    bool _computeOptimized)
    : // Use cryptographically strong pseudorandom number because
      // we will extract SipHash secret key from this
      sipHashNonce(GetRand(std::numeric_limits<uint64_t>::max())),
      nSize(0), nWaitingFor(0), shorttxidk0(0), shorttxidk1(0), version(_version), computeOptimized(_computeOptimized)
{
    SetNull();
    *((CSubBlock *)this) = pblock;
    nBlockTxs = pblock.vtx.size();
    uint64_t grapheneSetVersion = CSBGrapheneBlock::GetGrapheneSetVersion(version);

    if (version >= 2)
        FillShortTxIDSelector();

    std::vector<uint256> blockHashes;
    for (const auto &tx : pblock.vtx)
    {
        blockHashes.push_back(tx->GetHash());

        if (tx->IsProofBase())
            vAdditionalTxs.push_back(tx);
    }

    if (fCanonicalTxsOrder)
        pGrapheneSet =
            std::make_shared<CGrapheneSet>(CGrapheneSet(nReceiverMemPoolTx, nSenderMempoolPlusBlock, blockHashes,
                shorttxidk0, shorttxidk1, grapheneSetVersion, (uint32_t)sipHashNonce, computeOptimized, false));
    else
        pGrapheneSet = std::make_shared<CGrapheneSet>(CGrapheneSet(nReceiverMemPoolTx, nSenderMempoolPlusBlock,
            blockHashes, shorttxidk0, shorttxidk1, grapheneSetVersion, (uint32_t)sipHashNonce, computeOptimized, true));
}

CSBGrapheneBlock::~CSBGrapheneBlock() { pGrapheneSet = nullptr; }
void CSBGrapheneBlock::FillShortTxIDSelector()
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce << sipHashNonce;
    CSHA256 hasher;
    hasher.Write((unsigned char *)&(*stream.begin()), stream.end() - stream.begin());
    uint256 shorttxidhash;
    hasher.Finalize(shorttxidhash.begin());
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

void CSBGrapheneBlock::AddNewTransactions(std::vector<CTransaction> vMissingTx, CNode *pfrom)
{
    if (vMissingTx.size() == 0)
        return;

    // If canonical ordering is activated, locate empty indexes in vTxHashes256 to be used in sorting
    std::vector<size_t> missingTxIdxs;
    if (fCanonicalTxsOrder && SBNegotiateGrapheneVersion(pfrom) >= 1)
    {
        uint256 nullhash;
        for (size_t idx = 0; idx < vTxHashes256.size(); idx++)
        {
            if (vTxHashes256[idx] == nullhash)
                missingTxIdxs.push_back(idx);
        }
    }

    if (vMissingTx.size() != missingTxIdxs.size())
        throw std::runtime_error("Could not accommodate all vMissingTx in vTxHashes256");

    size_t idx = 0;
    for (const CTransaction &tx : vMissingTx)
    {
        mapMissingTx[SBGetShortID(pfrom->gr_shorttxidk0.load(), pfrom->gr_shorttxidk1.load(), tx.GetHash(),
            SBNegotiateGrapheneVersion(pfrom))] = MakeTransactionRef(tx);

        uint256 hash = tx.GetHash();
        uint64_t cheapHash = SBGetShortID(
            pfrom->gr_shorttxidk0.load(), pfrom->gr_shorttxidk1.load(), hash, SBNegotiateGrapheneVersion(pfrom));

        // Insert in arbitrary order if canonical ordering is enabled and extversion is recent enough
        if (fCanonicalTxsOrder && SBNegotiateGrapheneVersion(pfrom) >= 1)
        {
            if (idx >= missingTxIdxs.size())
                throw std::runtime_error("Range exceeded in missingTxIdxs");
            vTxHashes256[missingTxIdxs[idx]] = hash;
            idx++;
        }
        // Otherwise, use ordering information
        else
            vTxHashes256[mapHashOrderIndex[cheapHash]] = hash;
    }
}

void CSBGrapheneBlock::OrderTxHashes(CNode *pfrom)
{
    if (vTxHashes256.size() != nBlockTxs)
    {
        throw std::runtime_error("Cannot OrderTxHashes if size of vTxHashes256 unequal to nBlockTxs");
    }

    // Sort order transactions if canonical order is enabled and graphene version is late enough
    if (fCanonicalTxsOrder && SBNegotiateGrapheneVersion(pfrom) >= 1)
    {
        // coinbase is always first
        std::sort(vTxHashes256.begin() + 1, vTxHashes256.end());
        LOG(GRAPHENE, "Using canonical order for block from peer=%s\n", pfrom->GetLogName());
    }
    else
    {
        uint256 nullhash;
        std::vector<uint256> orderedTxHashes256(nBlockTxs, nullhash);
        for (auto &hash : vTxHashes256)
        {
            uint64_t cheapHash = SBGetShortID(
                pfrom->gr_shorttxidk0.load(), pfrom->gr_shorttxidk1.load(), hash, SBNegotiateGrapheneVersion(pfrom));
            const auto &orderIdx = mapHashOrderIndex.find(cheapHash);
            if (orderIdx == mapHashOrderIndex.end())
                throw std::runtime_error("Could not locate cheapHash in mapHashOrderIndex");
            orderedTxHashes256[orderIdx->second] = hash;
        }
        std::copy(orderedTxHashes256.begin(), orderedTxHashes256.end(), vTxHashes256.begin());
    }
}

bool CSBGrapheneBlock::ValidateAndRecontructBlock(uint256 blockhash,
    std::shared_ptr<CSBGrapheneBlock> pblock,
    const std::map<uint64_t, CTransactionRef> &mapCheapHashTx,
    std::string command,
    CNode *pfrom,
    CDataStream &vRecv)
{
    size_t msgSize = vRecv.size();
    OrderTxHashes(pfrom);

    // At this point we should have all the full hashes in the block. Check that the merkle
    // root in the block header matches the merkel root calculated from the hashes provided.
    bool mutated;
    uint256 merkleroot = ComputeMerkleRoot(vTxHashes256, &mutated);
    if (hashMerkleRoot != merkleroot || mutated)
    {
        thinrelay.ClearAllBlockData(pfrom, GetHash());
        return error("Merkle root for block %s does not match computed merkle root, peer=%s", blockhash.ToString(),
            pfrom->GetLogName());
    }
    LOG(GRAPHENE, "Merkle Root check passed for block %s peer=%s\n", blockhash.ToString(), pfrom->GetLogName());

    // Look for each transaction in our various pools and buffers.
    // With grapheneBlocks recovered txs contains only the first 8 bytes of the tx hash.
    {
        if (!ReconstructBlock(pfrom, pblock.get(), mapCheapHashTx))
            return false;
    }

    // We have all the transactions now that are in this block: try to reassemble and process.
    CInv inv2(MSG_BLOCK, blockhash);

    // for compression statistics, we have to add up the size of grapheneblock and the re-requested grapheneBlockTx.
    uint64_t nSizeGrapheneBlockTx = msgSize;
    uint64_t blockSize = GetBlockSize();
    float nCompressionRatio = 0.0;
    if (GetSize() + nSizeGrapheneBlockTx > 0)
        nCompressionRatio = (float)blockSize / ((float)GetSize() + (float)nSizeGrapheneBlockTx);
    LOG(GRAPHENE, "Reassembled grblktx for %s (%d bytes). Message was %d bytes (graphene block) and %d bytes "
                  "(re-requested tx), compression ratio %3.2f, peer=%s\n",
        GetHash().ToString(), blockSize, GetSize(), nSizeGrapheneBlockTx, nCompressionRatio,
        pfrom->GetLogName());

    // Update run-time statistics of graphene block bandwidth savings.
    // We add the original graphene block size with the size of transactions that were re-requested.
    // This is NOT double counting since we never accounted for the original graphene block due to the re-request.
    sb_graphenedata.UpdateInBound(nSizeGrapheneBlockTx + GetSize(), blockSize);
    LOG(GRAPHENE, "Graphene block stats: %s\n", sb_graphenedata.ToString());

    // Create full subblock
    tailstormDagSet.Insert(*(pblock.get()));

    return true;
}

CSBGrapheneBlockTx::CSBGrapheneBlockTx(uint256 blockHash, std::vector<CTransaction> &vTx)
{
    blockhash = blockHash;
    vMissingTx = vTx;
}

bool CSBGrapheneBlockTx::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    std::string strCommand = NetMsgType::SB_GRAPHENETX;
    CSBGrapheneBlockTx grapheneBlockTx;
    vRecv >> grapheneBlockTx;

    auto pblock = GetSBGBlockToReconstruct(pfrom, grapheneBlockTx.blockhash);
    if (pblock == nullptr)
        return error("No block available to reconstruct for graphenetx");
    DbgAssert(pblock != nullptr, return false);

    // Message consistency checking
    CInv inv(MSG_SB_GRAPHENEBLOCK, grapheneBlockTx.blockhash);
    if (grapheneBlockTx.vMissingTx.empty())
    {
        // Normal effect if the IBLT decode on the other side completely failed
        std::shared_ptr<CSBGrapheneBlock> backup = std::make_shared<CSBGrapheneBlock>(*pblock);
        SBRequestFailoverBlock(pfrom, backup.get());
        return error("Incorrectly constructed grblocktx data received, Empty tx set from: %s", pfrom->GetLogName());
    }
    if (grapheneBlockTx.blockhash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error(
            "Incorrectly constructed grblocktx  data received, hash is NULL.  Banning peer=%s", pfrom->GetLogName());
    }

    LOG(GRAPHENE, "Received grblocktx for %s peer=%s\n", inv.hash.ToString(), pfrom->GetLogName());
    {
        // Do not process unrequested grblocktx unless from an expedited node.
        if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::SB_GRAPHENEBLOCK, inv.hash) &&
            !connmgr->IsExpeditedUpstream(pfrom))
        {
            dosMan.Misbehaving(pfrom, 10);
            return error(
                "Received grblocktx %s from peer %s but was unrequested", inv.hash.ToString(), pfrom->GetLogName());
        }
    }

    // Copy backup block for failover
    std::shared_ptr<CSBGrapheneBlock> backup = std::make_shared<CSBGrapheneBlock>(*(pblock.get()));
    if (pblock->vTxHashes256.size() < grapheneBlockTx.vMissingTx.size())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("Inconsistent graphene block data received.  Banning peer=%s", pfrom->GetLogName());
    }

    // Check if we've already received this block and have it on disk
    if (AlreadyHaveBlock(inv))
    {
        requester.AlreadyReceived(pfrom, inv);
        thinrelay.ClearAllBlockData(pfrom, inv.hash);

        LOG(GRAPHENE, "Received grblocktx but returning because we already have this block %s on disk, peer=%s\n",
            inv.hash.ToString(), pfrom->GetLogName());
        return true;
    }

    // In the rare event of an erroneous checksum during IBLT decoding, the receiver may
    // have requested an invalid cheap hash, and the sender would have simply skipped sending
    // it. In that case, the number of missing txs returned will be fewer than the number
    // needed. Because the graphene block will be incomplete without the missing txs, we
    // request a failover block instead.
    if (grapheneBlockTx.vMissingTx.size() < pblock->nWaitingFor)
    {
        SBRequestFailoverBlock(pfrom, backup.get());
        return error("Still missing transactions from those returned by sender, peer=%s: re-requesting failover block",
            pfrom->GetLogName());
    }

    pblock->AddNewTransactions(grapheneBlockTx.vMissingTx, pfrom);

    LOG(GRAPHENE, "Got %d Re-requested txs from peer=%s\n", grapheneBlockTx.vMissingTx.size(), pfrom->GetLogName());

    std::map<uint64_t, CTransactionRef> mapPartialTxHash;
    pblock->FillTxMapFromPools(mapPartialTxHash);

    // Add full transactions included in the block
    for (auto &tx : pblock->vAdditionalTxs)
    {
        const uint256 &hash = tx->GetHash();
        uint64_t cheapHash = pblock->pGrapheneSet->GetShortID(hash);
        mapPartialTxHash.insert(std::make_pair(cheapHash, tx));
    }

    // Add full transactions collected during failure recovery
    for (auto &tx : pblock->vRecoveredTxs)
    {
        const uint256 &hash = tx->GetHash();
        uint64_t cheapHash = pblock->pGrapheneSet->GetShortID(hash);
        mapPartialTxHash.insert(std::make_pair(cheapHash, tx));
    }

    // Add full transactions from grapheneBlockTx.vMissingTx
    for (auto &tx : grapheneBlockTx.vMissingTx)
    {
        CTransactionRef txRef = MakeTransactionRef(tx);
        const uint256 &hash = tx.GetHash();
        uint64_t cheapHash = pblock->pGrapheneSet->GetShortID(hash);
        mapPartialTxHash.insert(std::make_pair(cheapHash, txRef));
    }

    if (!pblock->ValidateAndRecontructBlock(
            grapheneBlockTx.blockhash, pblock, mapPartialTxHash, strCommand, pfrom, vRecv))
    {
        SBRequestFailoverBlock(pfrom, backup.get());
        return error("Graphene ValidateAndRecontructBlock failed");
    }

    return true;
}

CSBRequestGrapheneBlockTx::CSBRequestGrapheneBlockTx(uint256 blockHash, std::set<uint64_t> &setHashesToRequest)
{
    blockhash = blockHash;
    setCheapHashesToRequest = setHashesToRequest;
}

bool CSBRequestGrapheneBlockTx::HandleMessage(CDataStream &vRecv, CNode *pfrom)
{
    CSBRequestGrapheneBlockTx grapheneRequestBlockTx;
    vRecv >> grapheneRequestBlockTx;
    uint256 blkHash = grapheneRequestBlockTx.blockhash;

    // Message consistency checking
    if (grapheneRequestBlockTx.setCheapHashesToRequest.empty() || blkHash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("Incorrectly constructed get_grblocktx received.  Banning peer=%s", pfrom->GetLogName());
    }

    LOG(GRAPHENE, "Received get_grblocktx for %s peer=%s\n", blkHash.ToString(), pfrom->GetLogName());

    try
    {
        std::vector<CTransaction> vTx =
            SBTransactionsFromBlockByCheapHash(grapheneRequestBlockTx.setCheapHashesToRequest, blkHash, pfrom);
        CSBGrapheneBlockTx grapheneBlockTx(grapheneRequestBlockTx.blockhash, vTx);
        pfrom->PushMessage(NetMsgType::SB_GRAPHENETX, grapheneBlockTx);
        pfrom->txsSent += vTx.size();
        if (vTx.size() == 0)
        {
            LOG(GRAPHENE, "Sent empty grapheneBlockTx.  Requested %d\n",
                grapheneRequestBlockTx.setCheapHashesToRequest.size());
        }
    }
    catch (const std::exception &e)
    {
        return error(GRAPHENE, e.what());
    }

    return true;
}

bool CSBGrapheneBlock::CheckBlockHeader(const CSubBlockHeader &block, CValidationState &state)
{
    // Check proof of work matches claimed amount
    if (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
    {
        return state.DoS(50, error("CheckBlockHeader(): proof of work failed"), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    {
        return state.Invalid(
            error("CheckBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= chainActive.Tip()->GetMedianTimePast())
    {
        return state.Invalid(error("%s: block's timestamp is too early", __func__), REJECT_INVALID, "time-too-old");
    }

    return true;
}

/**
 * Handle an incoming graphene block
 * Once the block is validated apart from the Merkle root, forward the Xpedited block with a hop count of nHops.
 */

 // TODO : rework this entire function
bool HandleSBGMessage(CDataStream &vRecv, CNode *pfrom, std::string strCommand, unsigned nHops)
{
    // Deserialize grapheneblock and store a block to reconstruct
    CSBGrapheneBlock tmp(SBNegotiateGrapheneVersion(pfrom), SBNegotiateFastFilterSupport(pfrom));
    vRecv >> tmp;
    std::shared_ptr<CSBGrapheneBlock> grapheneBlock = SetSBGBlockToReconstruct(pfrom, tmp);

    LOG(GRAPHENE, "Block %s from peer %s using Graphene version %d\n", grapheneBlock->GetHash().ToString(),
        pfrom->GetLogName(), grapheneBlock->version);

    // Message consistency checking (FIXME: some redundancy here with AcceptBlockHeader)
    if (!SBIsGrapheneBlockValid(pfrom, *(grapheneBlock.get())))
    {
        dosMan.Misbehaving(pfrom, 100);
        thinrelay.ClearAllBlockData(pfrom, grapheneBlock->GetHash());
        return error("Received an invalid %s from peer %s\n", strCommand, pfrom->GetLogName());
    }

    // Is there a previous block or header to connect with?
    if (!LookupBlockIndex(grapheneBlock->hashPrevBlock))
    {
        dosMan.Misbehaving(pfrom, 10);
        thinrelay.ClearAllBlockData(pfrom, grapheneBlock->GetHash());
        return error(GRAPHENE, "Graphene block from peer %s will not connect, unknown previous block %s",
            pfrom->GetLogName(), grapheneBlock->hashPrevBlock.ToString());
    }

    {
        LOCK(cs_main);
        CValidationState state;

        CInv inv(MSG_SB_GRAPHENEBLOCK, grapheneBlock->GetHash());
        // requester.UpdateBlockAvailability(pfrom->GetId(), inv.hash);

        // Return early if we already have the block data
        if (tailstormDagSet.Contains(inv.hash))
        {
            // Tell the Request Manager we received this block
            requester.AlreadyReceived(pfrom, inv);

            thinrelay.ClearAllBlockData(pfrom, inv.hash);
            LOG(GRAPHENE, "Received grapheneblock but returning because we already have block data %s from peer %s hop"
                          " %d size %d bytes\n",
                inv.hash.ToString(), pfrom->GetLogName(), nHops, grapheneBlock->GetSize());
            return true;
        }

        {
            LOG(GRAPHENE, "Received %s %s from peer %s. Size %d bytes.\n", strCommand, inv.hash.ToString(),
                pfrom->GetLogName(), grapheneBlock->GetSize());

            // Do not process unrequested grapheneblocks.
            if (!thinrelay.IsBlockInFlight(pfrom, NetMsgType::SB_GRAPHENEBLOCK, inv.hash))
            {
                dosMan.Misbehaving(pfrom, 10);
                return error(
                    "%s %s from peer %s but was unrequested\n", strCommand, inv.hash.ToString(), pfrom->GetLogName());
            }
        }
    }
    bool result = grapheneBlock->process(pfrom, strCommand);
    return result;
}

void CSBGrapheneBlock::FillTxMapFromPools(std::map<uint64_t, CTransactionRef> &mapTxFromPools)
{
    {
        boost::unique_lock<boost::mutex> lock(csCommitQ);
        for (auto &kv : *txCommitQ)
        {
            uint64_t cheapHash = SBGetShortID(shorttxidk0, shorttxidk1, kv.first, version);
            auto shTx = kv.second.entry.GetSharedTx();
            if (shTx != nullptr)
                mapTxFromPools.insert(std::make_pair(cheapHash, shTx));
        }
    }

    {
        READLOCK(orphanpool.cs_orphanpool);
        for (auto &kv : orphanpool.mapOrphanTransactions)
        {
            uint64_t cheapHash = SBGetShortID(shorttxidk0, shorttxidk1, kv.first, version);
            auto shTx = kv.second.ptx;
            if (shTx != nullptr)
                mapTxFromPools.insert(std::make_pair(cheapHash, shTx));
        }
    }

    std::vector<uint256> memPoolHashes;
    mempool.queryHashes(memPoolHashes);

    for (const uint256 &hash : memPoolHashes)
    {
        uint64_t cheapHash = SBGetShortID(shorttxidk0, shorttxidk1, hash, version);
        auto shTx = mempool.get(hash);
        if (shTx != nullptr) // otherwise mempool got updated between the query and this iteration
            mapTxFromPools.insert(std::make_pair(cheapHash, shTx));
    }
}

void CSBGrapheneBlock::SituateCoinbase(std::vector<uint64_t> blockCheapHashes,
    CTransactionRef coinbase,
    uint64_t grapheneVersion)
{
    // Ensure coinbase is first
    if (blockCheapHashes[0] != SBGetShortID(shorttxidk0, shorttxidk1, coinbase->GetHash(), version))
    {
        auto it = std::find(blockCheapHashes.begin(), blockCheapHashes.end(),
            SBGetShortID(shorttxidk0, shorttxidk1, coinbase->GetHash(), version));

        if (it == blockCheapHashes.end())
            throw std::runtime_error("No coinbase transaction found in graphene block");

        auto idx = std::distance(blockCheapHashes.begin(), it);

        blockCheapHashes[idx] = blockCheapHashes[0];
        blockCheapHashes[0] = SBGetShortID(shorttxidk0, shorttxidk1, coinbase->GetHash(), version);
    }
}

void CSBGrapheneBlock::SituateCoinbase(CTransactionRef coinbase)
{
    std::vector<uint256>::iterator it = std::find(vTxHashes256.begin(), vTxHashes256.end(), coinbase->GetHash());

    if (it == vTxHashes256.end())
        return;

    std::swap(vTxHashes256[0], vTxHashes256[std::distance(vTxHashes256.begin(), it)]);
}

std::set<uint64_t> CSBGrapheneBlock::UpdateResolvedTxsAndIdentifyMissing(
    const std::map<uint64_t, CTransactionRef> &mapPartialTxHash,
    const std::vector<uint64_t> &blockCheapHashes,
    uint64_t grapheneVersion)
{
    std::set<uint64_t> setHashesToRequest;
    uint256 nullhash;

    // Sort out what hashes we have from the complete set of cheapHashes
    for (size_t i = 0; i < blockCheapHashes.size(); i++)
    {
        uint64_t cheapHash = blockCheapHashes[i];

        // If canonical order is not enabled or extversion is less than 1, update mapHashOrderIndex so
        // it is available if we later receive missing txs
        if (!fCanonicalTxsOrder || grapheneVersion < 1)
            mapHashOrderIndex[cheapHash] = i;

        const auto &elem = mapPartialTxHash.find(cheapHash);
        if ((elem != mapPartialTxHash.end()) && (elem->second != nullptr))
        {
            const auto repeat = std::find(vTxHashes256.begin(), vTxHashes256.end(), elem->second->GetHash());
            if (repeat == vTxHashes256.end())
                vTxHashes256.push_back(elem->second->GetHash());
        }
        else
        {
            vTxHashes256.push_back(nullhash);
            setHashesToRequest.insert(cheapHash);
        }
    }

    return setHashesToRequest;
}

bool CSBGrapheneBlock::process(CNode *pfrom, std::string strCommand)
{
    // In PV we must prevent two graphene blocks from simulaneously processing that were recieved from the
    // same peer. This would only happen as in the example of an expedited block coming in
    // after an graphene request, because we would never explicitly request two graphene blocks from the same peer.
    if (PV->IsAlreadyValidating(pfrom->id, GetHash()))
    {
        LOGA("Not processing this grapheneblock from %s because %s is already validating in another thread\n",
            pfrom->GetLogName(), GetHash().ToString().c_str());
        return false;
    }

    pfrom->gr_shorttxidk0.store(shorttxidk0);
    pfrom->gr_shorttxidk1.store(shorttxidk1);

    // Create a map of all 8 bytes tx hashes pointing to their full tx hash counterpart
    bool fRequestFailureRecovery = false;
    std::set<uint256> passingTxHashes;
    std::map<uint64_t, CTransactionRef> mapPartialTxHash;
    std::set<uint64_t> setHashesToRequest;
    std::vector<uint256> vSenderFilterPositiveHahses;

    bool fMerkleRootCorrect = true;
    {
        FillTxMapFromPools(mapPartialTxHash);

        // Add full transactions included in the block
        CTransactionRef coinbase = nullptr;
        for (auto &tx : vAdditionalTxs)
        {
            const uint256 &hash = tx->GetHash();
            uint64_t cheapHash = SBGetShortID(shorttxidk0, shorttxidk1, hash, version);
            mapPartialTxHash.insert(std::make_pair(cheapHash, tx));

            if (tx->IsProofBase())
                coinbase = tx;
        }

        if (coinbase == nullptr)
        {
            LOG(GRAPHENE, "Error: No coinbase transaction found in graphene block, peer=%s", pfrom->GetLogName());
            return false;
        }

        try
        {
            std::set<uint64_t> setSenderFilterPositiveCheapHashes;

            // Populate tx hash array and cheap hash set for use by Graphene.
            // Do it outside of CGrapheneSet so that we can reuse the tx hashes
            // if failure recovery is necessary.
            bool grSetComputeOpt = pGrapheneSet->GetComputeOptimized();
            for (const auto &entry : mapPartialTxHash)
            {
                auto txptr = entry.second;
                if (entry.second == 0)
                {
                    LOG(GRAPHENE, "Error: Empty transaction in mapPartialTxHash");
                }
                else
                {
                    if ((grSetComputeOpt && pGrapheneSet->GetFastFilter()->contains(entry.second->GetHash())) ||
                        (!grSetComputeOpt && pGrapheneSet->GetRegularFilter()->contains(entry.second->GetHash())))
                    {
                        setSenderFilterPositiveCheapHashes.insert(entry.first);
                        vSenderFilterPositiveHahses.push_back(entry.second->GetHash());
                    }
                }
            }

            std::vector<uint64_t> blockCheapHashes = pGrapheneSet->Reconcile(setSenderFilterPositiveCheapHashes);
            setHashesToRequest = UpdateResolvedTxsAndIdentifyMissing(
                mapPartialTxHash, blockCheapHashes, SBNegotiateGrapheneVersion(pfrom));
            SituateCoinbase(coinbase);

            // Sort order transactions if canonical order is enabled and graphene version is late enough
            if (fCanonicalTxsOrder && SBNegotiateGrapheneVersion(pfrom) >= 1)
            {
                // coinbase is always first
                std::sort(vTxHashes256.begin() + 1, vTxHashes256.end());
                LOG(GRAPHENE, "Using canonical order for block from peer=%s\n", pfrom->GetLogName());
            }
        }
        catch (const std::runtime_error &e)
        {
            fRequestFailureRecovery = true;
            sb_graphenedata.IncrementDecodeFailures();
            if (version >= 6)
            {
                LOG(GRAPHENE, "Graphene set could not be reconciled; requesting recovery from peer %s: %s\n",
                    pfrom->GetLogName(), e.what());
            }
            else
            {
                LOG(GRAPHENE, "Graphene set could not be reconciled; requesting failover for peer %s: %s\n",
                    pfrom->GetLogName(), e.what());
            }
        }

        // Reconstruct the block if there are no hashes to re-request
        if (setHashesToRequest.empty() && !fRequestFailureRecovery)
        {
            bool mutated;
            uint256 merkleroot = ComputeMerkleRoot(vTxHashes256, &mutated);
            if (hashMerkleRoot != merkleroot || mutated)
                fMerkleRootCorrect = false;
            else
            {
                if (!ReconstructBlock(pfrom, this, mapPartialTxHash))
                    return false;
            }
        }

    } // End locking cs_orphancache, mempool.cs
    LOG(GRAPHENE, "Current in-memory graphene bytes size is %ld bytes\n", nCurrentBlockSize);

    // This must be checked outside of the above section or deadlock may occur.
    if (fRequestFailureRecovery)
    {
        SBRequestFailureRecovery(pfrom, *this, vSenderFilterPositiveHahses);
        return true;
    }

    // These must be checked outside of the mempool.cs lock or deadlock may occur.
    // A merkle root mismatch here does not cause a ban because and expedited node will forward an graphene
    // without checking the merkle root, therefore we don't want to ban our expedited nodes. Just request
    // a failover block if a mismatch occurs.
    if (!fMerkleRootCorrect)
    {
        SBRequestFailoverBlock(pfrom, this);
        return error(
            "Mismatched merkle root on grapheneblock: requesting failover block, peer=%s", pfrom->GetLogName());
    }

    this->nWaitingFor = setHashesToRequest.size();
    LOG(GRAPHENE, "Graphene subblock waiting for: %d, total txns: %d received txns: %d\n", this->nWaitingFor,
        vtx.size(), mapMissingTx.size());

    // If there are any missing hashes or transactions then we request them here.
    // This must be done outside of the mempool.cs lock or may deadlock.
    if (setHashesToRequest.size() > 0)
    {
        this->nWaitingFor = setHashesToRequest.size();
        CSBRequestGrapheneBlockTx grapheneBlockTx(GetHash(), setHashesToRequest);
        pfrom->PushMessage(NetMsgType::GET_SB_GRAPHENETX, grapheneBlockTx);

        // Update run-time statistics of graphene block bandwidth savings
        sb_graphenedata.UpdateInBoundReRequestedTx(this->nWaitingFor);

        return true;
    }

    // We now have all the transactions that are in this block
    this->nWaitingFor = 0;
    int blockSize = GetBlockSize();
    float nCompressionRatio = 0.0;
    if (GetSize() > 0)
        nCompressionRatio = (float)blockSize / (float)GetSize();
    LOG(GRAPHENE,
        "Reassembled graphene block for %s (%d bytes). Message was %d bytes, compression ratio %3.2f, peer=%s\n",
        GetHash().ToString(), blockSize, GetSize(), nCompressionRatio, pfrom->GetLogName());

    // Update run-time statistics of graphene block bandwidth savings
    sb_graphenedata.UpdateInBound(GetSize(), blockSize);
    LOG(GRAPHENE, "Graphene block stats: %s\n", sb_graphenedata.ToString().c_str());

    // Create full subblock
    ProcessNewSubBlock(*this);
    return true;
}

template <class T>
void CSBGrapheneBlockData::expireStats(std::map<int64_t, T> &statsMap)
{
    AssertLockHeld(cs_graphenestats);
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
void CSBGrapheneBlockData::updateStats(std::map<int64_t, T> &statsMap, T value)
{
    AssertLockHeld(cs_graphenestats);
    statsMap[getTimeForStats()] = value;
    expireStats(statsMap);
}

/**
   Calculate average of values in map. Return 0 for no entries.
   Expires values before calculation. */
double CSBGrapheneBlockData::average(std::map<int64_t, uint64_t> &map)
{
    AssertLockHeld(cs_graphenestats);

    expireStats(map);

    if (map.size() == 0)
        return 0.0;

    uint64_t accum = 0U;
    for (std::pair<int64_t, uint64_t> p : map)
    {
        // avoid wraparounds
        accum = std::max(accum, accum + p.second);
    }
    return (double)accum / map.size();
}

double CSBGrapheneBlockData::computeTotalBandwidthSavingsInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_graphenestats)
{
    AssertLockHeld(cs_graphenestats);

    return double(nOriginalSize() - nGrapheneSize() - nTotalMemPoolInfoBytes());
}

double CSBGrapheneBlockData::compute24hAverageCompressionInternal(
    std::map<int64_t, std::pair<uint64_t, uint64_t> > &mapGrapheneBlocks,
    std::map<int64_t, uint64_t> &mapMemPoolInfo) EXCLUSIVE_LOCKS_REQUIRED(cs_graphenestats)
{
    AssertLockHeld(cs_graphenestats);

    expireStats(mapGrapheneBlocks);
    expireStats(mapMemPoolInfo);

    double nCompressionRate = 0;
    uint64_t nGrapheneSizeTotal = 0;
    uint64_t nOriginalSizeTotal = 0;
    for (const auto &mi : mapGrapheneBlocks)
    {
        nGrapheneSizeTotal += mi.second.first;
        nOriginalSizeTotal += mi.second.second;
    }
    // We count up the CSBMemPoolInfo sizes from the opposite direction as the blocks.
    // Outbound CSBMemPoolInfo sizes go with Inbound graphene blocks and vice versa.
    uint64_t nMemPoolInfoSize = 0;
    for (const auto &mi : mapMemPoolInfo)
    {
        nMemPoolInfoSize += mi.second;
    }

    if (nOriginalSizeTotal > 0)
        nCompressionRate = 100 - (100 * (double)(nGrapheneSizeTotal + nMemPoolInfoSize) / nOriginalSizeTotal);

    return nCompressionRate;
}

double CSBGrapheneBlockData::compute24hInboundRerequestTxPercentInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_graphenestats)
{
    AssertLockHeld(cs_graphenestats);

    expireStats(mapGrapheneBlocksInBoundReRequestedTx);
    expireStats(mapGrapheneBlocksInBound);

    double nReRequestRate = 0;
    uint64_t nTotalReRequests = 0;
    uint64_t nTotalReRequestedTxs = 0;
    for (const auto &mi : mapGrapheneBlocksInBoundReRequestedTx)
    {
        nTotalReRequests += 1;
        nTotalReRequestedTxs += mi.second;
    }

    if (mapGrapheneBlocksInBound.size() > 0)
        nReRequestRate = 100 * (double)nTotalReRequests / mapGrapheneBlocksInBound.size();

    return nReRequestRate;
}

void CSBGrapheneBlockData::IncrementDecodeFailures()
{
    LOCK(cs_graphenestats);
    nDecodeFailures += 1;
}

void CSBGrapheneBlockData::UpdateInBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_graphenestats);
    // Update InBound graphene block tracking information
    nOriginalSize += nOriginalBlockSize;
    nGrapheneSize += nGrapheneBlockSize;
    nInBoundBlocks += 1;
    updateStats(mapGrapheneBlocksInBound, std::pair<uint64_t, uint64_t>(nGrapheneBlockSize, nOriginalBlockSize));
}

void CSBGrapheneBlockData::UpdateOutBound(uint64_t nGrapheneBlockSize, uint64_t nOriginalBlockSize)
{
    LOCK(cs_graphenestats);
    nOriginalSize += nOriginalBlockSize;
    nGrapheneSize += nGrapheneBlockSize;
    nOutBoundBlocks += 1;
    updateStats(mapGrapheneBlocksOutBound, std::pair<uint64_t, uint64_t>(nGrapheneBlockSize, nOriginalBlockSize));
}

void CSBGrapheneBlockData::UpdateOutBoundMemPoolInfo(uint64_t nMemPoolInfoSize)
{
    LOCK(cs_graphenestats);
    nTotalMemPoolInfoBytes += nMemPoolInfoSize;
    updateStats(mapMemPoolInfoOutBound, nMemPoolInfoSize);
}

void CSBGrapheneBlockData::UpdateInBoundMemPoolInfo(uint64_t nMemPoolInfoSize)
{
    LOCK(cs_graphenestats);
    nTotalMemPoolInfoBytes += nMemPoolInfoSize;
    updateStats(mapMemPoolInfoInBound, nMemPoolInfoSize);
}

void CSBGrapheneBlockData::UpdateFilter(uint64_t nFilterSize)
{
    LOCK(cs_graphenestats);
    nTotalFilterBytes += nFilterSize;
    updateStats(mapFilter, nFilterSize);
}

void CSBGrapheneBlockData::UpdateIblt(uint64_t nIbltSize)
{
    LOCK(cs_graphenestats);
    nTotalIbltBytes += nIbltSize;
    updateStats(mapIblt, nIbltSize);
}

void CSBGrapheneBlockData::UpdateRank(uint64_t nRankSize)
{
    LOCK(cs_graphenestats);
    nTotalRankBytes += nRankSize;
    updateStats(mapRank, nRankSize);
}

void CSBGrapheneBlockData::UpdateGrapheneBlock(uint64_t nGrapheneBlockSize)
{
    LOCK(cs_graphenestats);
    nTotalGrapheneBlockBytes += nGrapheneBlockSize;
    updateStats(mapGrapheneBlock, nGrapheneBlockSize);
}

void CSBGrapheneBlockData::UpdateAdditionalTx(uint64_t nAdditionalTxSize)
{
    LOCK(cs_graphenestats);
    nTotalAdditionalTxBytes += nAdditionalTxSize;
    updateStats(mapAdditionalTx, nAdditionalTxSize);
}

void CSBGrapheneBlockData::UpdateResponseTime(double nResponseTime)
{
    LOCK(cs_graphenestats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && SBIsGrapheneBlockEnabled())
        updateStats(mapGrapheneBlockResponseTime, nResponseTime);
}

void CSBGrapheneBlockData::UpdateValidationTime(double nValidationTime)
{
    LOCK(cs_graphenestats);

    // only update stats if IBD is complete
    if (IsChainNearlySyncd() && SBIsGrapheneBlockEnabled())
        updateStats(mapGrapheneBlockValidationTime, nValidationTime);
}

void CSBGrapheneBlockData::UpdateInBoundReRequestedTx(int nReRequestedTx)
{
    LOCK(cs_graphenestats);

    // Update InBound graphene block tracking information
    updateStats(mapGrapheneBlocksInBoundReRequestedTx, nReRequestedTx);
}

std::string CSBGrapheneBlockData::ToString()
{
    LOCK(cs_graphenestats);
    double size = computeTotalBandwidthSavingsInternal();
    std::ostringstream ss;
    ss << nInBoundBlocks() << " inbound and " << nOutBoundBlocks() << " outbound graphene blocks have saved "
       << formatInfoUnit(size) << " of bandwidth with " << nDecodeFailures() << " local decode "
       << ((nDecodeFailures() == 1) ? "failure" : "failures");

    return ss.str();
}

// Calculate the graphene percentage compression over the last 24 hours
std::string CSBGrapheneBlockData::InBoundPercentToString()
{
    LOCK(cs_graphenestats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapGrapheneBlocksInBound, mapMemPoolInfoOutBound);

    // NOTE: Potential gotcha, compute24hInboundCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapGrapheneBlocksInBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapGrapheneBlocksInBound.size()
       << " Inbound graphene blocks (last 24hrs): " << nCompressionRate << "%";

    return ss.str();
}

// Calculate the graphene percentage compression over the last 24 hours
std::string CSBGrapheneBlockData::OutBoundPercentToString()
{
    LOCK(cs_graphenestats);

    double nCompressionRate = compute24hAverageCompressionInternal(mapGrapheneBlocksOutBound, mapMemPoolInfoInBound);

    // NOTE: Potential gotcha, compute24hOutboundCompressionInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapGrapheneBlocksOutBound
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Compression for " << mapGrapheneBlocksOutBound.size()
       << " Outbound graphene blocks (last 24hrs): " << nCompressionRate << "%";
    return ss.str();
}

// Calculate the average inbound graphene CSBMemPoolInfo size
std::string CSBGrapheneBlockData::InBoundMemPoolInfoToString()
{
    LOCK(cs_graphenestats);
    double avgMemPoolInfoSize = average(mapMemPoolInfoInBound);
    std::ostringstream ss;
    ss << "Inbound CSBMemPoolInfo size (last 24hrs) AVG: " << formatInfoUnit(avgMemPoolInfoSize);
    return ss.str();
}

// Calculate the average outbound graphene CSBMemPoolInfo size
std::string CSBGrapheneBlockData::OutBoundMemPoolInfoToString()
{
    LOCK(cs_graphenestats);
    double avgMemPoolInfoSize = average(mapMemPoolInfoOutBound);
    std::ostringstream ss;
    ss << "Outbound CSBMemPoolInfo size (last 24hrs) AVG: " << formatInfoUnit(avgMemPoolInfoSize);
    return ss.str();
}

std::string CSBGrapheneBlockData::FilterToString()
{
    LOCK(cs_graphenestats);
    double avgFilterSize = average(mapFilter);
    std::ostringstream ss;
    ss << "Bloom filter size (last 24hrs) AVG: " << formatInfoUnit(avgFilterSize);
    return ss.str();
}

std::string CSBGrapheneBlockData::IbltToString()
{
    LOCK(cs_graphenestats);
    double avgIbltSize = average(mapIblt);
    std::ostringstream ss;
    ss << "IBLT size (last 24hrs) AVG: " << formatInfoUnit(avgIbltSize);
    return ss.str();
}

std::string CSBGrapheneBlockData::RankToString()
{
    LOCK(cs_graphenestats);
    double avgRankSize = average(mapRank);
    std::ostringstream ss;
    ss << "Rank size (last 24hrs) AVG: " << formatInfoUnit(avgRankSize);
    return ss.str();
}

std::string CSBGrapheneBlockData::GrapheneBlockToString()
{
    LOCK(cs_graphenestats);
    double avgGrapheneBlockSize = average(mapGrapheneBlock);
    std::ostringstream ss;
    ss << "Graphene block size (last 24hrs) AVG: " << formatInfoUnit(avgGrapheneBlockSize);
    return ss.str();
}

std::string CSBGrapheneBlockData::AdditionalTxToString()
{
    LOCK(cs_graphenestats);
    double avgAdditionalTxSize = average(mapAdditionalTx);
    std::ostringstream ss;
    ss << "Graphene size additional txs (last 24hrs) AVG: " << formatInfoUnit(avgAdditionalTxSize);
    return ss.str();
}

// Calculate the graphene average response time over the last 24 hours
std::string CSBGrapheneBlockData::ResponseTimeToString()
{
    LOCK(cs_graphenestats);

    expireStats(mapGrapheneBlockResponseTime);

    std::vector<double> vResponseTime;

    double nResponseTimeAverage = 0;
    double nPercentile = 0;
    double nTotalResponseTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapGrapheneBlockResponseTime)
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

// Calculate the graphene average block validation time over the last 24 hours
std::string CSBGrapheneBlockData::ValidationTimeToString()
{
    LOCK(cs_graphenestats);
    expireStats(mapGrapheneBlockValidationTime);

    std::vector<double> vValidationTime;
    double nValidationTimeAverage = 0;
    double nPercentile = 0;
    double nTotalValidationTime = 0;
    double nTotalEntries = 0;
    for (const auto &mi : mapGrapheneBlockValidationTime)
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

// Calculate the graphene average tx re-requested ratio over the last 24 hours
std::string CSBGrapheneBlockData::ReRequestedTxToString()
{
    LOCK(cs_graphenestats);
    double nReRequestRate = compute24hInboundRerequestTxPercentInternal();

    // NOTE: Potential gotcha, compute24hInboundRerequestTxPercentInternal has a side-effect of calling
    //       expireStats which modifies the contents of mapGrapheneBlocksInBoundReRequestedTx
    // We currently rely on this side-effect for the string produced below
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1);
    ss << "Tx re-request rate (last 24hrs): " << nReRequestRate
       << "% Total re-requests:" << mapGrapheneBlocksInBoundReRequestedTx.size();
    return ss.str();
}

void CSBGrapheneBlockData::ClearGrapheneBlockStats()
{
    LOCK(cs_graphenestats);

    nOriginalSize.Clear();
    nGrapheneSize.Clear();
    nInBoundBlocks.Clear();
    nOutBoundBlocks.Clear();
    nDecodeFailures.Clear();
    nTotalMemPoolInfoBytes.Clear();
    nTotalFilterBytes.Clear();
    nTotalIbltBytes.Clear();
    nTotalRankBytes.Clear();
    nTotalGrapheneBlockBytes.Clear();

    mapGrapheneBlocksInBound.clear();
    mapGrapheneBlocksOutBound.clear();
    mapMemPoolInfoOutBound.clear();
    mapMemPoolInfoInBound.clear();
    mapFilter.clear();
    mapIblt.clear();
    mapRank.clear();
    mapGrapheneBlock.clear();
    mapGrapheneBlockResponseTime.clear();
    mapGrapheneBlockValidationTime.clear();
    mapGrapheneBlocksInBoundReRequestedTx.clear();
}

void CSBGrapheneBlockData::FillGrapheneQuickStats(SBGrapheneQuickStats &stats)
{
    if (!SBIsGrapheneBlockEnabled())
        return;

    LOCK(cs_graphenestats);
    stats.nTotalInbound = nInBoundBlocks();
    stats.nTotalOutbound = nOutBoundBlocks();
    stats.nTotalDecodeFailures = nDecodeFailures();
    stats.nTotalBandwidthSavings = computeTotalBandwidthSavingsInternal();

    // NOTE: The following calls rely on the side-effect of the compute*Internal
    //       calls also calling expireStats on the associated statistics maps
    //       This is why we set the % value first, then the count second for compression values
    stats.fLast24hInboundCompression =
        compute24hAverageCompressionInternal(mapGrapheneBlocksInBound, mapMemPoolInfoOutBound);
    stats.nLast24hInbound = mapGrapheneBlocksInBound.size();
    stats.fLast24hOutboundCompression =
        compute24hAverageCompressionInternal(mapGrapheneBlocksOutBound, mapMemPoolInfoInBound);
    stats.nLast24hOutbound = mapGrapheneBlocksOutBound.size();
    stats.fLast24hRerequestTxPercent = compute24hInboundRerequestTxPercentInternal();
    stats.nLast24hRerequestTx = mapGrapheneBlocksInBoundReRequestedTx.size();
}

bool SBIsGrapheneBlockEnabled() { return GetBoolArg("-use-grapheneblocks", DEFAULT_USE_GRAPHENE_BLOCKS); }
void SBSendGrapheneBlock(const CSubBlock &pblock, CNode *pfrom, const CInv &inv, const CSBMemPoolInfo &mempoolinfo)
{
    if (inv.type == MSG_SB_GRAPHENEBLOCK)
    {
        // exclude coinbase
        uint64_t nSenderMempoolPlusBlock = SBGetGrapheneMempoolInfo().nTx + pblock.vtx.size() - 1;

        CSBGrapheneBlock grapheneBlock(pblock, mempoolinfo.nTx, nSenderMempoolPlusBlock,
            SBNegotiateGrapheneVersion(pfrom), SBNegotiateFastFilterSupport(pfrom));

        LOG(GRAPHENE, "Block %s to peer %s using Graphene version %d\n", grapheneBlock.GetHash().ToString(),
            pfrom->GetLogName(), grapheneBlock.version);

        pfrom->gr_shorttxidk0.store(grapheneBlock.shorttxidk0);
        pfrom->gr_shorttxidk1.store(grapheneBlock.shorttxidk1);
        uint64_t nSizeBlock = pblock.GetBlockSize();
        uint64_t nSizeGrapheneBlock = grapheneBlock.GetSize();
        sb_graphenedata.UpdateOutBound(nSizeGrapheneBlock, nSizeBlock);
        pfrom->PushMessage(NetMsgType::SB_GRAPHENEBLOCK, grapheneBlock);

        // First add transaction hashes to local graphene block
        for (auto &tx : pblock.vtx)
        {
            grapheneBlock.vTxHashes256.push_back(tx->GetHash());
        }
        // Next store graphene block in case receiver attempts failure recovery
        SetSentSBGrapheneBlocks(pfrom->GetId(), grapheneBlock);
        LOG(GRAPHENE, "Sent graphene block - size: %d vs block size: %d => peer: %s\n", nSizeGrapheneBlock,
            nSizeBlock, pfrom->GetLogName());

        sb_graphenedata.UpdateFilter(grapheneBlock.pGrapheneSet->GetFilterSerializationSize());
        sb_graphenedata.UpdateIblt(grapheneBlock.pGrapheneSet->GetIbltSerializationSize());
        sb_graphenedata.UpdateRank(grapheneBlock.pGrapheneSet->GetRankSerializationSize());
        sb_graphenedata.UpdateGrapheneBlock(nSizeGrapheneBlock);
        sb_graphenedata.UpdateAdditionalTx(grapheneBlock.GetAdditionalTxSerializationSize());
    }
    else
    {
        dosMan.Misbehaving(pfrom, 100);

        return;
    }

    pfrom->blocksSent += 1;
}

bool SBIsGrapheneBlockValid(CNode *pfrom, const CSubBlockHeader &header)
{
    // check block header
    CValidationState state;
    if (!CheckSubBlockHeader(header, state, true))
    {
        return error("Received invalid header for graphene block %s from peer %s", header.GetHash().ToString(),
            pfrom->GetLogName());
    }
    if (state.Invalid())
    {
        return error("Received invalid header for graphene block %s from peer %s", header.GetHash().ToString(),
            pfrom->GetLogName());
    }

    return true;
}

bool SBHandleGrapheneBlockRequest(CDataStream &vRecv, CNode *pfrom, const CChainParams &chainparams)
{
    CSBMemPoolInfo mempoolinfo;
    CInv inv;
    vRecv >> inv >> mempoolinfo;
    sb_graphenedata.UpdateInBoundMemPoolInfo(::GetSerializeSize(mempoolinfo, SER_NETWORK, PROTOCOL_VERSION));

    // Message consistency checking
    if (!(inv.type == MSG_SB_GRAPHENEBLOCK) || inv.hash.IsNull())
    {
        dosMan.Misbehaving(pfrom, 100);
        return error("invalid GET_GRAPHENE message type=%u hash=%s", inv.type, inv.hash.ToString());
    }
    CSubBlock subblock;
    LOG(GRAPHENE, "GRAPHENE tailstormDagSet.Find %d\n", tailstormDagSet.Find(inv.hash, subblock));
    if (tailstormDagSet.Find(inv.hash, subblock))
    {
		SBSendGrapheneBlock(subblock, pfrom, inv, mempoolinfo);
    }
    else
	{
        std::map<uint256, CDagNode>::iterator iter;
        {
            LOCK(cs_tipDagCache);
            iter = tipDagCache.find(inv.hash);
            if (iter == tipDagCache.end())
            {
                return error("Peer %s requested tailstorm subblock %s that cannot be read", pfrom->GetLogName(), inv.hash.ToString());
            }
            subblock = iter->second.subblock;
        }
        SBSendGrapheneBlock(subblock, pfrom, inv, mempoolinfo);
	}
    return true;
}

bool SBHandleGrapheneBlockRecoveryRequest(CDataStream &vRecv, CNode *pfrom, const CChainParams &chainparams)
{
    CRequestGrapheneReceiverRecover recoveryRequest;
    vRecv >> recoveryRequest;

    std::shared_ptr<CSBGrapheneBlock> grapheneBlock = GetSentSBGrapheneBlocks(pfrom->GetId());
    if (!grapheneBlock)
        return error("No block available to reconstruct for get_grrec");

    // We had a block stored but it was the wrong one
    if (grapheneBlock->GetHash() != recoveryRequest.blockhash)
        return error("Sender does not have block for requested hash");

    CSBGrapheneReceiverRecover recoveryResponse = CSBGrapheneReceiverRecover(
        *recoveryRequest.pReceiverFilter, *grapheneBlock, recoveryRequest.nSenderFilterPositives, pfrom);
    pfrom->PushMessage(NetMsgType::SB_GRAPHENE_RECOVERY, recoveryResponse);

    return true;
}

bool SBHandleGrapheneBlockRecoveryResponse(CDataStream &vRecv, CNode *pfrom, const CChainParams &chainparams)
{
    CGrapheneReceiverRecover recoveryResponse;
    vRecv >> recoveryResponse;

    auto pblock = GetSBGBlockToReconstruct(pfrom, recoveryResponse.blockhash);
    if (pblock == nullptr)
        return error("No block available to reconstruct for grrec");
    CSBGrapheneBlock grapheneBlock = *(pblock.get());

    CIblt localIblt((*recoveryResponse.pRevisedIblt));
    localIblt.reset();

    // Initialize map with txs from various pools
    std::map<uint64_t, CTransactionRef> mapTxFromPools;
    pblock->FillTxMapFromPools(mapTxFromPools);

    // Insert additional txs and identify coinbase
    CTransactionRef coinbase = nullptr;
    for (auto &tx : pblock->vAdditionalTxs)
    {
        const uint256 &hash = tx->GetHash();
        uint64_t cheapHash = pblock->pGrapheneSet->GetShortID(hash);

        mapTxFromPools.insert(std::make_pair(cheapHash, tx));

        if (tx->IsProofBase())
            coinbase = tx;
    }

    if (coinbase == nullptr)
    {
        LOG(GRAPHENE, "Error: No coinbase transaction found in graphene block, peer=%s", pfrom->GetLogName());
        return false;
    }

    // Insert latest transactions just sent over
    for (auto &tx : recoveryResponse.vMissingTxs)
    {
        const uint256 &hash = tx.GetHash();
        uint64_t cheapHash = pblock->pGrapheneSet->GetShortID(hash);

        CTransactionRef txRef = MakeTransactionRef(tx);
        mapTxFromPools.insert(std::make_pair(cheapHash, txRef));
        pblock->mapMissingTx[cheapHash] = txRef;
        // Used during reconstruction if other txs need to be rerequested
        pblock->vRecoveredTxs.insert(txRef);
    }

    // Determine which txs pass filter and populate IBLT
    std::set<uint64_t> setSenderFilterPositiveCheapHashes;
    for (auto &pair : mapTxFromPools)
    {
        if ((pblock->pGrapheneSet->GetComputeOptimized() &&
                pblock->pGrapheneSet->GetFastFilter()->contains(pair.second->GetHash())) ||
            (!pblock->pGrapheneSet->GetComputeOptimized() &&
                pblock->pGrapheneSet->GetRegularFilter()->contains(pair.second->GetHash())))
        {
            localIblt.insert(pair.first, IBLT_NULL_VALUE);
            setSenderFilterPositiveCheapHashes.insert(pair.first);
        }
    }

    // Attempt to reconcile IBLT
    static std::vector<uint64_t> blockCheapHashes;
    try
    {
        blockCheapHashes = CGrapheneSet::Reconcile(setSenderFilterPositiveCheapHashes, localIblt,
            recoveryResponse.pRevisedIblt, pblock->pGrapheneSet->GetEncodedRank(),
            pblock->pGrapheneSet->GetOrdered());
    }
    catch (const std::runtime_error &error)
    {
        // Graphene set still could not be reconciled
        LOG(GRAPHENE, "Could not reconcile failure recovery Graphene set from peer=%s; requesting failover block\n",
            pfrom->GetLogName());
        SBRequestFailoverBlock(pfrom, pblock.get());
        return true;
    }

    LOG(GRAPHENE, "Successfully reconciled failure recovery Graphene set from peer=%s\n", pfrom->GetLogName());

    std::set<uint64_t> setHashesToRequest = pblock->UpdateResolvedTxsAndIdentifyMissing(
        mapTxFromPools, blockCheapHashes, SBNegotiateGrapheneVersion(pfrom));
    pblock->SituateCoinbase(coinbase);

    // If there are missing transactions, we must request them here
    if (setHashesToRequest.size() > 0)
    {
        pblock->nWaitingFor = setHashesToRequest.size();
        CSBRequestGrapheneBlockTx grapheneBlockTx(recoveryResponse.blockhash, setHashesToRequest);
        pfrom->PushMessage(NetMsgType::GET_SB_GRAPHENETX, grapheneBlockTx);

        // Update run-time statistics of graphene block bandwidth savings
        sb_graphenedata.UpdateInBoundReRequestedTx(grapheneBlock.nWaitingFor);

        return true;
    }

    if (!pblock->ValidateAndRecontructBlock(
            recoveryResponse.blockhash, pblock, mapTxFromPools, NetMsgType::SB_GRAPHENE_RECOVERY, pfrom, vRecv))
    {
        SBRequestFailoverBlock(pfrom, pblock.get());
        return error("Graphene ValidateAndRecontructBlock failed");
    }

    return true;
}

CSBRequestGrapheneReceiverRecover::CSBRequestGrapheneReceiverRecover(std::vector<uint256> &relevantHashes,
    CSBGrapheneBlock &grapheneBlock,
    uint64_t _nSenderFilterPositives)
{
    uint64_t grapheneSetVersion = CSBGrapheneBlock::GetGrapheneSetVersion(GRAPHENE_MAX_VERSION_SUPPORTED);
    nSenderFilterPositives = _nSenderFilterPositives;
    blockhash = grapheneBlock.GetHash();
    uint64_t nReceiverUniverseItems = (uint64_t)std::max(_nSenderFilterPositives,
        SBGetGrapheneMempoolInfo().nTx); // _nSenderFilterPositives could be larger when it contains the coinbase
    uint64_t nItems = grapheneBlock.nBlockTxs;
    pReceiverFilter = std::make_shared<CVariableFastFilter>(
        grapheneBlock.pGrapheneSet->FailureRecoveryFilter(relevantHashes, nItems, nSenderFilterPositives,
            nReceiverUniverseItems, FAILURE_RECOVERY_SUCCESS_RATE, grapheneBlock.fpr, grapheneSetVersion));

    sb_graphenedata.UpdateFilter(::GetSerializeSize(*pReceiverFilter, SER_NETWORK, PROTOCOL_VERSION));
}

CSBGrapheneReceiverRecover::CSBGrapheneReceiverRecover(CVariableFastFilter &receiverFilter,
    CSBGrapheneBlock &grapheneBlock,
    uint64_t nSenderFilterPositiveItems,
    CNode *pfrom)
{
    blockhash = grapheneBlock.GetHash();
    uint64_t grapheneSetVersion = CSBGrapheneBlock::GetGrapheneSetVersion(GRAPHENE_MAX_VERSION_SUPPORTED);
    uint64_t nReceiverUniverseItems = grapheneBlock.pGrapheneSet->GetNReceiverUniverseItems();
    uint64_t nItems = grapheneBlock.nBlockTxs;

    std::vector<uint256> vMissingTxIds;
    std::set<uint64_t> vAllCheapHashes;
    std::set<uint64_t> vMissingCheapHashes;
    for (auto &hash : grapheneBlock.vTxHashes256)
    {
        if (!receiverFilter.contains(hash))
            vMissingTxIds.push_back(hash);
        else
            vMissingCheapHashes.insert(grapheneBlock.pGrapheneSet->GetShortID(hash));

        vAllCheapHashes.insert(grapheneBlock.pGrapheneSet->GetShortID(hash));
    }

    pRevisedIblt = std::make_shared<CIblt>(grapheneBlock.pGrapheneSet->FailureRecoveryIblt(vAllCheapHashes, nItems,
        nSenderFilterPositiveItems, nReceiverUniverseItems, FAILURE_RECOVERY_SUCCESS_RATE, grapheneBlock.fpr,
        grapheneSetVersion, (uint32_t)grapheneBlock.shorttxidk0));
    std::vector<CTransaction> vTx = SBTransactionsFromBlockByCheapHash(vMissingCheapHashes, blockhash, pfrom);
    std::copy(vTx.begin(), vTx.end(), back_inserter(vMissingTxs));

    sb_graphenedata.UpdateIblt(::GetSerializeSize(*pRevisedIblt, SER_NETWORK, PROTOCOL_VERSION));
}

CSBMemPoolInfo SBGetGrapheneMempoolInfo()
{
    // We need the number of transactions in the mempool and orphanpools but also the number
    // in the txCommitQ that have been processed and valid, and which will be in the mempool shortly.
    uint64_t nCommitQ = 0;
    {
        boost::unique_lock<boost::mutex> lock(csCommitQ);
        nCommitQ = txCommitQ->size();
    }
    return CSBMemPoolInfo(mempool.size() + orphanpool.GetOrphanPoolSize() + nCommitQ);
}

void SBRequestFailureRecovery(CNode *pfrom,
    CSBGrapheneBlock &grapheneBlock,
    std::vector<uint256> vSenderFilterPositiveHahses)
{
    CSBRequestGrapheneReceiverRecover recoveryRequest = CSBRequestGrapheneReceiverRecover(
        vSenderFilterPositiveHahses, grapheneBlock, vSenderFilterPositiveHahses.size());

    pfrom->PushMessage(NetMsgType::GET_SB_GRAPHENE_RECOVERY, recoveryRequest);
}

void SBRequestFailoverBlock(CNode *pfrom, CSBGrapheneBlock* subblock)
{
    // Since we were unable process this graphene block then clear out the data and the graphene
    // block in flight making sure to get the blockhash before you clear all the data.
    //
    // This must be done before we request the failover block otherwise it will still appear
    // as though we have a graphene block in flight, which could prevent us from receiving
    // the recovery block.
    uint256 blockhash = subblock->GetHash();
    thinrelay.ClearAllBlockData(pfrom, blockhash);

    LOG(GRAPHENE, "Requesting full subblock %s as failover from peer %s\n", blockhash.ToString(), pfrom->GetLogName());
    CInv inv(MSG_SUBBLOCK, blockhash);
    std::vector<CInv> vGetData;
    vGetData.push_back(inv);
    pfrom->PushMessage(NetMsgType::GETDATA, vGetData);
}

std::vector<CTransaction> SBTransactionsFromBlockByCheapHash(std::set<uint64_t> &vCheapHashes,
    uint256 blockhash,
    CNode *pfrom)
{
	CSubBlock subblock;
    std::vector<CTransaction> vTx;
	if (!tailstormDagSet.Find(blockhash, subblock))
    {
        throw std::runtime_error("Requested block is not available");
    }
    else
    {
		for (auto &tx : subblock.vtx)
        {
			uint64_t cheapHash = SBGetShortID(pfrom->gr_shorttxidk0.load(), pfrom->gr_shorttxidk1.load(),
				tx->GetHash(), SBNegotiateGrapheneVersion(pfrom));

			if (vCheapHashes.count(cheapHash))
				vTx.push_back(*tx);
        }
    }

    return vTx;
}

// Generate cheap hash from seeds using SipHash
uint64_t SBGetShortID(uint64_t shorttxidk0, uint64_t shorttxidk1, const uint256 &txhash, uint64_t grapheneVersion)
{
    if (grapheneVersion < 2)
        return txhash.GetCheapHash();

    // If both shorttxidk0 and shorttxidk1 are equal to 0, then it is very likely
    // that the values have not been properly instantiated using FillShortTxIDSelector,
    // but are instead unchanged from the default initialization value.
    DbgAssert(!(shorttxidk0 == 0 && shorttxidk1 == 0), );

    static_assert(SHORTTXIDS_LENGTH == 8, "shorttxids calculation assumes 8-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffffL;
}

bool SBNegotiateFastFilterSupport(CNode *pfrom)
{
    uint64_t peerFastFilterPref;
    {
        LOCK(pfrom->cs_extversion);
        peerFastFilterPref = pfrom->extversion.as_u64c(XVer::BU_GRAPHENE_FAST_FILTER_PREF);
    }

    if (grapheneFastFilterCompatibility.Value() == EITHER)
    {
        if (peerFastFilterPref == EITHER)
            return true;
        else if (peerFastFilterPref == FAST)
            return true;
        else
            return false;
    }
    else if (grapheneFastFilterCompatibility.Value() == FAST)
    {
        if (peerFastFilterPref == EITHER)
            return true;
        else if (peerFastFilterPref == FAST)
            return true;
        else
            throw std::runtime_error("Sender and receiver have incompatible fast filter preferences");
    }
    else
    {
        if (peerFastFilterPref == EITHER)
            return false;
        else if (peerFastFilterPref == FAST)
            throw std::runtime_error("Sender and receiver have incompatible fast filter preferences");
        else
            return false;
    }
}

uint64_t SBNegotiateGrapheneVersion(CNode *pfrom)
{
    uint64_t selfMax = grapheneMaxVersionSupported.Value();
    uint64_t selfMin = grapheneMinVersionSupported.Value();
    uint64_t peerMin, peerMax;
    {
        LOCK(pfrom->cs_extversion);
        peerMin = pfrom->extversion.as_u64c(XVer::BU_GRAPHENE_MIN_VERSION_SUPPORTED);
        peerMax = pfrom->extversion.as_u64c(XVer::BU_GRAPHENE_MAX_VERSION_SUPPORTED);
    }

    uint64_t upper = (uint64_t)std::min(peerMax, selfMax);
    uint64_t lower = (uint64_t)std::max(peerMin, selfMin);

    if (lower > upper)
        throw std::runtime_error("Sender and receiver support incompatible Graphene versions");

    return upper;
}
