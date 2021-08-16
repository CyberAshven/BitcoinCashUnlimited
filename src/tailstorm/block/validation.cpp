// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "tailstorm/dag.h"
#include "tailstorm/pow.h"
#include "validation.h"

// other bitcoin includes
#include "blockrelay/blockrelay_common.h"
#include "blockstorage/blockstorage.h"
#include "blockstorage/sequential_files.h"
#include "checkpoints.h"
#include "connmgr.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "dosman.h"
#include "expedited.h"
#include "index/txindex.h"
#include "init.h"
#include "net.h"
#include "requestManager.h"
#include "sync.h"
#include "timedata.h"
#include "txadmission.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "validation/validation.h"
#include "validationinterface.h"

#include <boost/scope_exit.hpp>
#include <unordered_set>

extern bool fCheckForPruning;
extern std::map<uint256, NodeId> mapBlockSource;
extern uint64_t nBlockSequenceId;
extern std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked;
extern std::set<CBlockIndex *, CBlockIndexWorkComparator> setBlockIndexCandidates GUARDED_BY(cs_main);

extern bool AbortNode(CValidationState &state, const std::string &strMessage, const std::string &userMessage = "");
extern int ApplyTxInUndo(Coin &&undo, CCoinsViewCache &view, const COutPoint &out);

bool InitTailstormBlockIndex(const CChainParams &chainparams)
{
    LOCK(cs_main);

    // Initialize global variables that cannot be constructed at startup.

    // Check whether we're already initialized
    if (chainActive.Genesis() != nullptr)
        return true;

    LOGA("Initializing databases...\n");

    try
    {
        CTailstormBlock block = chainparams.GenesisTailstormBlock();
        // Start new block file
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        CValidationState state;
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.GetBlockTime()))
        {
            return error("LoadBlockIndex(): FindBlockPos failed");
        }
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
        {
            return error("LoadBlockIndex(): writing genesis block to disk failed");
        }
        CBlockIndex *pindex = AddToBlockIndex(block);
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
        {
            return error("LoadBlockIndex(): genesis block not accepted");
        }
        if (!ActivateBestChainTailstorm(state, chainparams, &block))
        {
            return error("LoadBlockIndex(): genesis block cannot be activated");
        }
        // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
        return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
    }
    catch (const std::runtime_error &e)
    {
        return error("LoadBlockIndex(): failed to initialize block database: %s", e.what());
    }

    return true;
}

bool CheckTailstormBlockHeader(const CTailstormBlockHeader &header, CValidationState &state)
{
    // Check proof-of-work
    if (!CheckTailstormPoW(header, Params().GetConsensus(), TAILSTORM_K))
    {
        return state.DoS(50, error("%s(): tailstorm block validity check failed", __func__), REJECT_INVALID, "high-hash");
    }
    // Check timestamp
    if (header.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    {
        return state.Invalid(
            error("%s(): block timestamp too far in the future", __func__), REJECT_INVALID, "time-too-new");
    }
    return true;
}

bool ContextualCheckBlockHeader(const CTailstormBlockHeader &block, CValidationState &state, CBlockIndex *const pindexPrev)
{
    const Consensus::Params &consensusParams = Params().GetConsensus();
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Check proof of work
    uint32_t expectedNbits = GetNextWorkRequired(pindexPrev, block.GetBlockTime(), consensusParams);
    if (block.nBits != expectedNbits)
    {
        return state.DoS(100, error("%s: incorrect proof of work. Height %d, Block nBits 0x%x, expected 0x%x", __func__,
                                  nHeight, block.nBits, expectedNbits),
            REJECT_INVALID, "bad-diffbits");
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
    {
        return state.Invalid(error("%s: block's timestamp is too early", __func__), REJECT_INVALID, "time-too-old");
    }

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if ((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
        (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
        (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
    {
        return state.Invalid(
            error("%s: rejected nVersion=0x%08x block", __func__, block.nVersion), REJECT_OBSOLETE, "bad-version");
    }

    return true;
}

static void NotifyHeaderTip()
{
    if (!pindexBestHeader.load())
        return;

    static std::atomic<CBlockIndex *> pindexHeaderOld{pindexBestHeader.load()};
    static std::atomic<int64_t> nLastTime{0};
    if (pindexBestHeader.load()->nChainWork > pindexHeaderOld.load()->nChainWork &&
        (GetTime() - nLastTime > 1 || !IsInitialBlockDownload()))
    {
        uiInterface.NotifyHeaderTip(false, pindexBestHeader.load(), true);
        pindexHeaderOld.store(pindexBestHeader.load());
        nLastTime = GetTime();
    }
}

CBlockIndex *AddToBlockIndex(const CTailstormBlockHeader &block)
{
    WRITELOCK(cs_mapBlockIndex);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
    {
        return it->second;
    }

    // Construct new block index object
    CBlockIndex *pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
        // If the prior block or an ancestor has failed, mark this one failed
        if (pindexNew->pprev && pindexNew->pprev->nStatus & BLOCK_FAILED_MASK)
        {
            pindexNew->nStatus |= BLOCK_FAILED_CHILD;
        }
    }
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);

    // If the block belongs to the set of check-pointed blocks but it has a mismatched hash,
    // then we are on the wrong fork so ignore.
    if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexNew->nHeight, *pindexNew->phashBlock, Params()))
    {
        pindexNew->nStatus |= BLOCK_FAILED_VALID; // block doesn't match checkpoints so invalid
        pindexNew->nStatus &= ~BLOCK_VALID_CHAIN;
    }

    // Lastly, set the best header if this is a valid header on a valid chain and if the chain work
    // is higher than the previous best header.
    CBlockIndex *pBestHeader = pindexBestHeader.load();
    if ((!(pindexNew->nStatus & BLOCK_FAILED_MASK)) &&
        (pBestHeader == nullptr || pBestHeader->nChainWork < pindexNew->nChainWork))
    {
        pindexBestHeader.store(pindexNew);
    }

    // Update the ui if the best header has changed.
    NotifyHeaderTip();

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

bool AcceptTailstormBlockHeader(const CTailstormBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock)
    {
        pindex = LookupBlockIndex(hash);
        if (pindex)
        {
            // Block header is already known.
            if (ppindex)
                *ppindex = pindex;
            {
                READLOCK(cs_mapBlockIndex);
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return state.Invalid(
                        error("%s: subblock %s height %d is marked invalid", __func__, hash.ToString(), pindex->nHeight),
                        0, "duplicate");
            }
            return true;
        }

        if (!CheckTailstormBlockHeader(block, state))
            return false;

        // Get prev block index
        CBlockIndex *pindexPrev = LookupBlockIndex(block.hashPrevBlock);
        if (!pindexPrev)
            return state.DoS(10, error("%s: previous block %s not found while accepting %s", __func__,
                                     block.hashPrevBlock.ToString(), hash.ToString()),
                0, "bad-prevblk");
        {
            READLOCK(cs_mapBlockIndex);
            if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
                return state.DoS(100,
                    error("%s: previous block %s is invalid", __func__, pindexPrev->GetBlockHash().GetHex().c_str()),
                    REJECT_INVALID, "bad-prevblk");
        }

        // If the parent block belongs to the set of checkpointed blocks but it has a mismatched hash,
        // then we are on the wrong fork so ignore
        if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexPrev->nHeight, *pindexPrev->phashBlock, chainparams))
            return error("%s: CheckAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, pindexPrev))
            return false;
    }
    if (pindex == nullptr)
    {
        pindex = AddToBlockIndex(block);
    }

    if (ppindex)
    {
        *ppindex = pindex;
    }

    return true;
}


bool ContextualCheckTailstormBlock(const CTailstormBlock &block,
    CValidationState &state,
    CBlockIndex *const pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params &consensusParams = Params().GetConsensus();

    // Start enforcing BIP113 (Median Time Past)
    int nLockTimeFlags = 0;
    if (nHeight >= consensusParams.BIP68Height)
    {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff;
    if (pindexPrev == nullptr)
        nLockTimeCutoff = block.GetBlockTime();
    else
        nLockTimeCutoff =
            (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST) ? pindexPrev->GetMedianTimePast() : block.GetBlockTime();

    // Check that all transactions are finalized and count the number of
    // transactions to check for excessive transaction limits.
    uint64_t nTx = 0;
    uint64_t nLargestTx = 0;
    for (const auto &tx : block.vtx)
    {
        if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
        {
            return state.DoS(
                10, error("%s: contains a non-final transaction", __func__), REJECT_INVALID, "bad-txns-nonfinal");
        }
        if (!ContextualCheckTransaction(tx, state, pindexPrev, Params()))
            return false;

        nTx++;
        if (tx->GetTxSize() > nLargestTx)
            nLargestTx = tx->GetTxSize();
    }

    // Enforce block nVersion=2 rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height)
    {
        // For legacy reasons keep the original way of checking BIP34 compliance
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin()))
        {
            // However the original way only checks a specific serialized int encoding, BUT BIP34 does not mandate
            // the most efficient encoding, only that it be a "serialized CScript", and then gives an example with
            // 3 byte encoding.  Therefore we've ended up with miners that only generate 3 byte encodings...
            int blockCoinbaseHeight = block.GetHeight();
            if (blockCoinbaseHeight == nHeight)
            {
                LOG(BLK, "Mined block valid but suboptimal height format, different client interpretions of "
                         "BIP34 may cause fork");
            }
            else
            {
                uint256 hashp = block.hashPrevBlock;
                uint256 hash = block.GetHash();
                return state.DoS(100, error("%s: block height mismatch in coinbase, expected %d, got %d, block is %s, "
                                            "parent block is %s, pprev is %s",
                                          __func__, nHeight, blockCoinbaseHeight, hash.ToString(), hashp.ToString(),
                                          pindexPrev->phashBlock->ToString()),
                    REJECT_INVALID, "bad-cb-height");
            }
        }
    }

    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev == nullptr ? 1 : pindexPrev->nHeight + 1;

    return true;
}

bool TestTailstormBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CTailstormBlock &block,
    CBlockIndex *pindexPrev,
    bool fCheckPOW,
    bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    // Ensure that if there is a checkpoint on this height, that this block is the one.
    if (fCheckpointsEnabled && !CheckAgainstCheckpoint(pindexPrev->nHeight + 1, block.GetHash(), chainparams))
    {
        return error("%s: CheckAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());
    }
    CCoinsViewCache viewNew(pcoinsTip);
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;
    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!CheckTailstormBlockHeader(block, state))
    {
        return false;
    }
    if (!ContextualCheckTailstormBlock(block, state, pindexPrev))
    {
        return false;
    }
    if (!ConnectTailstormBlock(block, state, &indexDummy, viewNew, chainparams, true))
    {
        return false;
    }
    assert(state.IsValid());
    return true;
}

bool CheckTailstormBlock(const CTailstormBlock &block, CValidationState &state)
{
    if (!CheckTailstormPoW(block, Params().GetConsensus(), TAILSTORM_K))
    {
        return state.DoS(50, error("%s(): tailstorm proof of work failed", __func__), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    {
        return state.Invalid(error("%s(): block timestamp too far in the future", __func__), REJECT_INVALID, "time-too-new");
    }

    // These are checks that are independent of context.

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckTailstormBlockHeader(block, state))
    {
        return false;
    }

    // Check the merkle root.
    bool mutated;
    uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
    if (block.hashMerkleRoot != hashMerkleRoot2)
    {
        LOGA("%s != %s \n", block.hashMerkleRoot.ToString().c_str(), hashMerkleRoot2.ToString().c_str());
        return state.DoS(
            100, error("%s(): hashMerkleRoot mismatch", __func__), REJECT_INVALID, "bad-txnmrklroot", true);
    }
    // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    // of transactions in a block without affecting the merkle root of a block,
    // while still invalidating it.
    if (mutated)
    {
        return state.DoS(
            100, error("%s(): duplicate transaction", __func__), REJECT_INVALID, "bad-txns-duplicate", true);
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (block.vtx.empty())
    {
        return state.DoS(100, error("%s(): size limits failed", __func__), REJECT_INVALID, "bad-blk-length");
    }

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
    {
        return state.DoS(100, error("%s(): first tx is not coinbase", __func__), REJECT_INVALID, "bad-cb-missing");
    }

    for (unsigned int i = 1; i < block.vtx.size(); i++)
    {
        if (block.vtx[i]->IsCoinBase())
        {
            return state.DoS(100, error("%s(): more than one coinbase", __func__), REJECT_INVALID, "bad-cb-multiple");
        }
    }

    // Check transactions
    for (const auto &tx : block.vtx)
    {
        if (!CheckTransaction(tx, state))
        {
            return error("%s(): CheckTransaction of %s failed with %s", __func__, tx->GetHash().ToString(),
                FormatStateMessage(state));
        }
    }

    return true;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CTailstormBlock &block,
    CValidationState &state,
    CBlockIndex *pindexNew,
    const CDiskBlockPos &pos)
{
    AssertLockHeld(cs_main); // for setBlockIndexCandidates
    WRITELOCK(cs_mapBlockIndex); // for nStatus and nSequenceId

    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;

    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->nChainTx)
    {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex *> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty())
        {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            pindex->nSequenceId = ++nBlockSequenceId;
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip()))
            {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second)
            {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    }
    else
    {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE))
        {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool AcceptTailstormBlock(const CTailstormBlock &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex,
    bool fRequested,
    CDiskBlockPos *dbp)
{
    AssertLockHeld(cs_main);

    CBlockIndex *&pindex = *ppindex;

    if (!AcceptTailstormBlockHeader(block, state, chainparams, &pindex))
    {
        return false;
    }

    LOG(PARALLEL, "Check TailstormBlock %s with chain work %s block height %d\n", pindex->phashBlock->ToString(),
        pindex->nChainWork.ToString(), pindex->nHeight);

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = false;
    {
        READLOCK(cs_mapBlockIndex);
        fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    }
    bool fHasMoreWork = (chainActive.Tip() ? pindex->nChainWork > chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave)
    {
        return true;
    }
    // If we didn't ask for it:
    if (!fRequested)
    {
        if (pindex->nTx != 0)
            return true; // This is a previously-processed block that was pruned
        if (!fHasMoreWork)
            return true; // Don't process less-work chains
        if (fTooFarAhead)
            return true; // Block height is too high
    }
    if ((!CheckTailstormBlock(block, state)) || !ContextualCheckTailstormBlock(block, state, pindex->pprev))
    {
        if (state.IsInvalid() && !state.CorruptionPossible())
        {
            {
                WRITELOCK(cs_mapBlockIndex);
                pindex->nStatus |= BLOCK_FAILED_VALID;
                setDirtyBlockIndex.insert(pindex);
            }
            // Now mark every block index on every chain that contains pindex as child of invalid
            MarkAllContainingChainsInvalid(pindex);
        }
        return false;
    }
    int nHeight = pindex->nHeight;
    // Write block to history file
    try
    {
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != nullptr)
        {
            blockPos = *dbp;
        }
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, block.GetBlockTime(), dbp != nullptr))
        {
            return error("%s(): FindBlockPos failed", __func__);
        }
        if (dbp == nullptr)
        {
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
            {
                AbortNode(state, "Failed to write block");
            }
        }
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
        {
            return error("%s(): ReceivedBlockTransactions failed", __func__);
        }
    }
    catch (const std::runtime_error &e)
    {
        return AbortNode(state, std::string("System error: ") + e.what());
    }
    if (fCheckForPruning)
    {
        FlushStateToDisk(state, FLUSH_STATE_NONE); // we just allocated more disk space for block files
    }
    return true;
}

bool ConnectTailstormBlock(const CTailstormBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    bool fJustCheck)
{
    // pindex should be the header structure for this new block
    assert(pindex->hashMerkleRoot == block.hashMerkleRoot);

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock)
    {
        if (!fJustCheck)
        {
            view.SetBestBlock(pindex->GetBlockHash());
        }
        return true;
    }

    AssertLockHeld(cs_main);

    // Check it again in case a previous version let a bad block in
    if (!CheckTailstormBlock(block, state))
    {
        return false;
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                         !((pindex->nHeight == 91842 &&
                               pindex->GetBlockHash() ==
                                   uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                             (pindex->nHeight == 91880 &&
                                 pindex->GetBlockHash() ==
                                     uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create
    // further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for
    // the BIP30 check.
    if (pindex->pprev) // If this isn't the genesis block
    {
        CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
        // Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't
        // correspond.
        fEnforceBIP30 =
            fEnforceBIP30 &&
            (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

        if (fEnforceBIP30)
        {
            for (const auto &tx : block.vtx)
            {
                for (size_t o = 0; o < tx->vout.size(); o++)
                {
                    if (view.HaveCoin(COutPoint(tx->GetHash(), o)))
                    {
                        return state.DoS(100, error("%s(): tried to overwrite transaction", __func__), REJECT_INVALID,
                            "bad-txns-BIP30");
                    }
                }
            }
        }
    }

    const int64_t timeBarrier = GetTime() - (24 * 3600 * checkScriptDays.Value());
    // Blocks that have various days of POW behind them makes them secure in that
    // real online nodes have checked the scripts.  Therefore, during initial block
    // download we don't need to check most of those scripts except for the most
    // recent ones.
    bool fScriptChecks = true;
    CBlockIndex *pBestHeader = pindexBestHeader.load();
    if (pBestHeader)
    {
        if (fReindex || fImporting)
            fScriptChecks = !fCheckpointsEnabled || block.nTime > timeBarrier;
        else
            fScriptChecks = !fCheckpointsEnabled || block.nTime > timeBarrier ||
                            (uint32_t)pindex->nHeight > pBestHeader->nHeight - (144 * checkScriptDays.Value());
    }

    CAmount nFees = 0;
    CBlockUndo blockundo;
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());

    nFees = 0;
    LOG(BLK, "Canonical ordering for %s MTP: %d\n", block.GetHash().ToString(), pindex->GetMedianTimePast());

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY)
    int nLockTimeFlags = 0;
    if (pindex->nHeight >= chainparams.GetConsensus().BIP68Height)
    {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Get the script flags for this block
    uint32_t flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());

    std::vector<ValidationResourceTracker> txResourceTracker;
    std::vector<int> prevheights;
    int nInputs = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    int nChecked = 0;
    int nUnVerifiedChecked = 0;

    // Get the next available mutex and the associated scriptcheckqueue. Then lock this thread
    // with the mutex so that the checking of inputs can be done with the chosen scriptcheckqueue.
    CCheckQueue<CScriptCheck> *pScriptQueue(PV->GetScriptCheckQueue());

    // Aquire the control that is used to wait for the script threads to finish. Do this after aquiring the
    // scoped lock to ensure the scriptqueue is free and available.
    CCheckQueueControl<CScriptCheck> control(fScriptChecks && PV->ThreadCount() ? pScriptQueue : nullptr);

    {
        txResourceTracker.resize(block.vtx.size());

        // Outputs then Inputs algorithm: add outputs to the coin cache
        // and validate lexical ordering
        uint256 prevTxHash;
        for (unsigned int i = 0; i < block.vtx.size(); i++)
        {
            const CTransaction &tx = *(block.vtx[i]);
            if (tx.IsProofBase())
            {
                continue;
            }
            try
            {
                AddCoins(view, tx, pindex->nHeight);
            }
            catch (std::logic_error &e)
            {
                return state.DoS(100,
                    error("%s: block %s repeated-tx %s", __func__, block.GetHash().ToString(), tx.GetHash().ToString()),
                    REJECT_INVALID, "repeated-txn");
            }

            if (i == 1)
            {
                prevTxHash = tx.GetHash();
            }
            else if (i != 0)
            {
                uint256 curTxHash = tx.GetHash();
                if (curTxHash < prevTxHash)
                {
                    return state.DoS(100,
                        error("%s: block %s lexical misordering tx %d (%s < %s)", __func__, block.GetHash().ToString(),
                                         i, curTxHash.ToString(), prevTxHash.ToString()),
                        REJECT_INVALID, "bad-txn-order");
                }
                prevTxHash = curTxHash;
            }
        }

        // Start checking Inputs
        // When in parallel mode then unlock cs_main for this loop to give any other threads
        // a chance to process in parallel. This is crucial for parallel validation to work.
        // NOTE: the only place where cs_main is needed is if we hit PV->ChainWorkHasChanged, which
        //       internally grabs the cs_main lock when needed.
        for (unsigned int i = 0; i < block.vtx.size(); i++)
        {
            const CTransaction &tx = *(block.vtx[i]);
            const CTransactionRef &txref = block.vtx[i];

            nInputs += tx.vin.size();

            if (!tx.IsCoinBase() && !tx.IsProofBase())
            {
                // Check that transaction is BIP68 final
                // BIP68 lock checks (as opposed to nLockTime checks) must
                // be in ConnectBlock because they require the UTXO set
                prevheights.resize(tx.vin.size());
                {
                    bool abort = false;
                    for (size_t j = 0; j < tx.vin.size(); j++)
                    {
                        CoinAccessor coin(view, tx.vin[j].prevout);
                        // isSpend is true for empty coin object (coinEmpty)
                        if (coin->IsSpent())
                        {
                            abort = true;
                            break;
                        }
                        prevheights[j] = coin->nHeight;
                        nFees = nFees + coin->out.nValue;
                    }
                    if (abort)
                    {
                        return state.DoS(100, error("%s: block %s inputs missing/spent in tx %d %s", __func__,
                                                  block.GetHash().ToString(), i, tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-txns-inputs-missingorspent");
                    }
                }
                nFees = nFees - tx.GetValueOut();

                if (!SequenceLocks(txref, nLockTimeFlags, &prevheights, *pindex))
                {
                    return state.DoS(100, error("%s: block %s contains a non-BIP68-final transaction", __func__,
                                              block.GetHash().ToString()),
                        REJECT_INVALID, "bad-txns-nonfinal");
                }

                uint256 hash = tx.GetHash();
                {
                    // If XVal is not on then check all inputs, otherwise only check
                    // transactions that were not previously verified in the mempool.
                    bool fUnVerified = block.setUnVerifiedTxns.count(hash);
                    if (fUnVerified)
                    {
                        if (fUnVerified)
                            nUnVerifiedChecked++;

                        std::vector<CScriptCheck> vChecks;
                        bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks
                                                            (still consult the cache, though) */
                        if (!CheckInputs(txref, state, view, fScriptChecks, flags, maxScriptOps.Value(), fCacheResults,
                                &txResourceTracker[i], PV->ThreadCount() ? &vChecks : nullptr))
                        {
                            return error("%s: block %s CheckInputs on %s failed with %s", __func__,
                                block.GetHash().ToString(), tx.GetHash().ToString(), FormatStateMessage(state));
                        }
                        control.Add(vChecks);
                        nChecked++;
                    }
                }
            }

            CTxUndo undoDummy;
            if (i > 0)
            {
                blockundo.vtxundo.push_back(CTxUndo());
            }

            SpendCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

            vPos.push_back(std::make_pair(tx.GetHash(), pos));
            pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
        }
        LOG(BENCH, "Number of CheckInputs() performed: %d  Unverified count: %d\n", nChecked, nUnVerifiedChecked);

        // Wait for all sig check threads to finish before updating utxo
        LOG(PARALLEL, "Waiting for script threads to finish\n");
        if (!control.Wait())
        {
            // if we end up here then the signature verification failed and we must re-lock cs_main before returning.
            return state.DoS(100, false, REJECT_INVALID, "bad-blk-signatures", false, "parallel script check failed");
        }

        uint64_t blockSigChecks = 0;
        for (const auto &t : txResourceTracker) // its ok to add the coinbase sigchecks because they must be 0
        {
            auto txSigChecks = t.GetConsensusSigChecks();
            blockSigChecks += txSigChecks;
            LOG(BENCH, "Tx SigChecks performed: %d\n", txSigChecks);
            // May2020 transaction consensus rule
            if (txSigChecks > MAY2020_MAX_TX_SIGCHECK_COUNT)
            {
                return state.DoS(100, false, REJECT_INVALID, "bad-tx-sigchecks", false,
                    "per transaction sigcheck limit exceeded");
            }
        }

        LOG(BENCH, "Number of SigChecks performed: %d\n", blockSigChecks);
        // May 2020 block consensus rule
        uint64_t maxSigChecksAllowed = maxSigChecks.Value();
        if (blockSigChecks > maxSigChecksAllowed)
        {
            return state.DoS(
                100, false, REJECT_INVALID, "bad-blk-sigchecks", false, "block sigcheck limit exceeded");
        }
    }

    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
    if (block.vtx[0]->GetValueOut() > blockReward)
    {
        return state.DoS(100, error("%s(): coinbase pays too much (actual=%d vs limit=%d)",
                                  __func__, block.vtx[0]->GetValueOut(), blockReward),
            REJECT_INVALID, "bad-cb-amount");
    }

    if (fJustCheck)
        return true;

    /*****************************************************************************************************************
     *                         Start update of UTXO, if this block wins the validation race *
     *****************************************************************************************************************/

    // Write undo information to disk
    {
        if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
        {
            if (pindex->GetUndoPos().IsNull())
            {
                CDiskBlockPos _pos;
                if (!FindUndoPos(
                        state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                {
                    return error("%s(): FindUndoPos failed", __func__);
                }
                // TODO maybe fix here
                if (!WriteUndoToDisk(blockundo, _pos, pindex->pprev))
                {
                    return AbortNode(state, "Failed to write undo data");
                }

                // update nUndoPos in block index
                //
                // We must take the cs_mapBlockIndex after FindUndoPos() in order to maintain
                // the proper locking order of cs_main -> cs_LastBlockFile -> cs_mapBlockIndex
                WRITELOCK(cs_mapBlockIndex);
                pindex->nUndoPos = _pos.nPos;
                pindex->nStatus |= BLOCK_HAVE_UNDO;
            }

            WRITELOCK(cs_mapBlockIndex);
            pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
            setDirtyBlockIndex.insert(pindex);
        }
    }

    // Write transaction data to the txindex
    if (fTxIndex)
    {
        g_txindex->BlockConnected(block, pindex);
    }

    // add this block to the view's block chain (the main UTXO in memory cache)
    view.SetBestBlock(pindex->GetBlockHash());

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase;
    GetMainSignals().UpdatedTransaction(hashPrevBestCoinBase);
    hashPrevBestCoinBase = block.vtx[0]->GetHash();

    // Track all recent txns in a block so we don't re-request them again. This can happen a txn announcement
    // arrives just after the block is received.
    for (const CTransactionRef &ptx : block.vtx)
    {
        txRecentlyInBlock.insert(ptx->GetHash());
    }

    return true;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When UNCLEAN or FAILED is returned, view is left in an indeterminate state. */
DisconnectResult DisconnectTailstormBlock(const CTailstormBlock &block, const CBlockIndex *pindex, CCoinsViewCache &view)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    // blockdb mode does not use the file pos system
    if (pos.IsNull() && BLOCK_DB_MODE == SEQUENTIAL_BLOCK_FILES)
    {
        error("DisconnectTailstormBlock(): no undo data available");
        return DISCONNECT_FAILED;
    }
    if (!ReadUndoFromDisk(blockUndo, pos, pindex->pprev))
    {
        error("DisconnectTailstormBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }
    if (blockUndo.vtxundo.size() + 1 != block.vtx.size())
    {
        error("DisconnectTailstormBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }
    // undo transactions in reverse of the OTI algorithm order (so add inputs first, then remove outputs)
    // we can use this algorithm for both dtor and ctor because we are undoing a validated block so
    // we already know that the block is valid.

    // restore inputs
    for (unsigned int i = 1; i < block.vtx.size(); i++) // i=1 to skip the coinbase, it has no inputs
    {
        const CTransaction &tx = *(block.vtx[i]);
        // skip proofbase txs. they are not real transactions
        if (tx.IsProofBase())
        {
            continue;
        }
        CTxUndo &txundo = blockUndo.vtxundo[i - 1];
        if (txundo.vprevout.size() != tx.vin.size())
        {
            error("DisconnectTailstormBlock(): transaction and undo data inconsistent");
            return DISCONNECT_FAILED;
        }
        for (unsigned int j = tx.vin.size(); j-- > 0;)
        {
            const COutPoint &out = tx.vin[j].prevout;
            int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
            if (res == DISCONNECT_FAILED)
            {
                error("DisconnectTailstormBlock(): ApplyTxInUndo failed");
                return DISCONNECT_FAILED;
            }
            fClean = fClean && res != DISCONNECT_UNCLEAN;
        }
        // At this point, all of txundo.vprevout should have been moved out.
    }

    // remove outputs
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the block itself exactly.
        for (size_t o = 0; o < tx.vout.size(); o++)
        {
            if (!tx.vout[o].scriptPubKey.IsUnspendable())
            {
                COutPoint out(hash, o);
                Coin coin;
                view.SpendCoin(out, &coin);
                if (tx.vout[o] != coin.out)
                {
                    error("DisconnectTailstormBlock(): transaction output mismatch");
                    fClean = false; // transaction output mismatch
                }
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectTipTailstorm(CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex *pindexNew,
    const CTailstormBlock *pblock)
{
    AssertLockHeld(cs_main);

    // During IBD if there are many blocks to connect still it could be a while before shutting down
    // and the user may think the shutdown has hung, so return here and stop connecting any remaining
    // blocks.
    if (ShutdownRequested())
        return false;

    // With PV there is a special case where one chain may be in the process of connecting several blocks but then
    // a second chain also begins to connect blocks and its block beat the first chains block to advance the tip.
    // As a result pindexNew->prev on the first chain will no longer match the chaintip as the second chain continues
    // connecting blocks. Therefore we must return "false" rather than "assert" as was previously the case.
    // assert(pindexNew->pprev == chainActive.Tip());
    if (pindexNew->pprev != chainActive.Tip())
        return false;

    // Read block from disk.
    CTailstormBlockRef block(new CTailstormBlock);
    if (!pblock)
    {
        if (!ReadBlockFromDisk(block, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "%s(): Failed to read block", __func__);
        pblock = block.get();
    }
    // Apply the block atomically to the chain state.
    {
        CCoinsViewCache view(pcoinsTip);
        bool rv = ConnectTailstormBlock(*pblock, state, pindexNew, view, chainparams, false);
        GetMainSignals().TailstormBlockChecked(*pblock, state);
        if (!rv)
        {
            if (state.IsInvalid())
            {
                InvalidBlockFound(pindexNew, state);
                return error("%s(): ConnectBlock %s failed", __func__, pindexNew->GetBlockHash().ToString());
            }
            return false;
        }
        bool result = view.Flush();
        nBlockSizeAtChainTip.store(pblock->GetBlockSize());
        assert(result);
        mapBlockSource.erase(pindexNew->GetBlockHash());
    }
    // Write the chain state to disk, if necessary, and only during IBD, reindex, or importing.
    if (!IsChainNearlySyncd() || fReindex || fImporting)
    {
        if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        {
            return false;
        }
    }

    // Remove transactions from the mempool, both those confirmed in the block and conflicting transactions.
    //
    // If we are still in initial block download then skip this step and just clear the mempool. There should
    // be no transactions in the mempool during initial sync, and also there is no need then to parse through each
    // blocks transactions in removeForBlock() looking for transactions to remove.
    std::list<CTransactionRef> txConflicted;
    if (!IsInitialBlockDownload() && !fReindex)
    {
        // txChanges: only if some unconfirmed tx push is turned on, track what transactions may need to be pushed while
        // confirmed transactions are removed from the mempool.
        mempool.removeForBlock(pblock->vtx, pindexNew->nHeight, txConflicted, !IsInitialBlockDownload());
    }
    else
    {
        mempool.clear();
    }
    // Update chainActive & related variables.
    UpdateTip(pindexNew);
    // Tell wallet about transactions that went from mempool
    // to conflicted:
    for (const auto &ptx : txConflicted)
    {
        SyncWithWallets(ptx, nullptr, -1);
    }
    // ... and about transactions that got confirmed:
    int txIdx = 0;
    for (const auto &ptx : pblock->vtx)
    {
        SyncWithWallets_BT(ptx, pblock, txIdx);
        txIdx++;
    }

    return true;
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 */
bool ActivateBestChainStepTailstorm(CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex *pindexMostWork,
    const CTailstormBlock *pblock)
{
    if (!pindexMostWork)
    {
        return false;
    }

    AssertLockHeld(cs_main);
    bool fInvalidFound = false;
    const CBlockIndex *pindexOldTip = chainActive.Tip();
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);
    CBlockIndex *pindexNewMostWork;

    bool fBlocksDisconnected = false;

    while (chainActive.Tip() && chainActive.Tip() != pindexFork)
    {
        // Disconnect active blocks which are no longer in the best chain. We do not need to concern ourselves with any
        // block validation threads that may be running for the chain we are rolling back. They will automatically fail
        // validation during ConnectBlock() once the chaintip has changed..
        if (!DisconnectTip(state, chainparams.GetConsensus()))
        {
            return false;
        }

        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex *> vpindexToConnect;
    bool fContinue = true;
    bool fBlock = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight < pindexMostWork->nHeight)
    {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + (int)requester.BLOCK_DOWNLOAD_WINDOW.load(), pindexMostWork->nHeight);
        vpindexToConnect.clear();
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight)
        {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        CBlockIndex *pindexNewTip = nullptr;
        CBlockIndex *pindexLastNotify = nullptr;
        for (auto i = vpindexToConnect.rbegin(); i != vpindexToConnect.rend(); i++)
        {
            // Start with a clear state in case we're connecting another block after
            // trying to connect an invalid on a different chain.
            state = CValidationState();

            CBlockIndex *pindexConnect = *i;
            // Check if the best chain has changed while we were disconnecting or processing blocks.
            // If so then we need to return and continue processing the newer chain.
            pindexNewMostWork = FindMostWorkChain();
            if (!pindexMostWork || !pindexNewMostWork)
            {
                return false;
            }

            if (pindexNewMostWork->nChainWork > pindexMostWork->nChainWork)
            {
                LOG(PARALLEL, "Returning because chain work has changed while connecting blocks\n");
                return true;
            }
            if (!ConnectTipTailstorm(state, chainparams, pindexConnect,
                    pindexConnect == pindexMostWork && fBlock ? pblock : nullptr))
            {
                if (state.IsInvalid())
                {
                    LOGA("%s(): Invalid block due to %s\n", __func__, state.GetRejectReason().c_str());

                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                    {
                        InvalidChainFound(vpindexToConnect.back());
                    }
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                }
                else
                {
                    // A system error occurred (disk space, database error, ...) or a Parallel Validation was
                    // terminated.
                    return false;
                }
            }
            else
            {
                pindexNewTip = pindexConnect;

                // Update the syncd status after each block is handled
                IsChainNearlySyncdInit();
                IsInitialBlockDownloadInit();

                if (!IsInitialBlockDownload())
                {
                    // Notify external zmq listeners about the new tip.
                    GetMainSignals().UpdatedBlockTip(pindexConnect);
                }

                // Update the UI at least every 5 seconds just in case we get in a long loop
                // as can happen during IBD.  We need an atomic here because there may be other
                // threads running concurrently.
                static std::atomic<int64_t> nLastUpdate = {GetTime()};
                if (nLastUpdate.load() < GetTime() - 5)
                {
                    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindexNewTip, false);
                    pindexLastNotify = pindexNewTip;
                    nLastUpdate.store(GetTime());
                }

                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork)
                {
                    fContinue = false;
                    break;
                }
            }

            // If we're shutting down then don't connect any more blocks.
            if (shutdown_threads.load())
                return false;
        }

        // Notify the UI with the new block tip information.
        if (pindexMostWork->nHeight >= nHeight && pindexNewTip != nullptr && pindexLastNotify != pindexNewTip)
            uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindexNewTip, false);

        if (fContinue)
        {
            pindexMostWork = FindMostWorkChain();
            if (!pindexMostWork)
                return false;
        }
        fBlock = false; // read next blocks from disk

        // Update the syncd status after each block is handled
        IsChainNearlySyncdInit();
        IsInitialBlockDownloadInit();
    }


    // Relay Inventory
    CBlockIndex *pindexNewTip = chainActive.Tip();
    if (pindexFork != pindexNewTip)
    {
        if (!IsInitialBlockDownload())
        {
            // Find the hashes of all blocks that weren't previously in the best chain.
            std::vector<uint256> vHashes;
            CBlockIndex *pindexToAnnounce = pindexNewTip;
            while (pindexToAnnounce != pindexFork)
            {
                vHashes.push_back(pindexToAnnounce->GetBlockHash());
                pindexToAnnounce = pindexToAnnounce->pprev;
                if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE)
                {
                    // Limit announcements in case of a huge reorganization.
                    // Rely on the peer's synchronization mechanism in that case.
                    break;
                }
            }
            // Relay inventory, but don't relay old inventory during initial block download.
            int nBlockEstimate = 0;
            if (fCheckpointsEnabled)
                nBlockEstimate = Checkpoints::GetTotalBlocksEstimate(chainparams.Checkpoints());
            {
                LOCK(cs_vNodes);
                for (CNode *pnode : vNodes)
                {
                    if (chainActive.Height() >
                        (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                    {
                        for (auto i = vHashes.rbegin(); i != vHashes.rend(); i++)
                        {
                            const uint256 &hash = *i;
                            pnode->PushBlockHash(hash);
                        }
                    }
                }
            }
        }
    }

    if (fBlocksDisconnected)
    {
        LimitMempoolSize(mempool, GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
            GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
    }
    mempool.check(pcoinsTip);

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
    {
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
        return false;
    }
    else
    {
        CheckForkWarningConditions();
    }

    return true;
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChainTailstorm(CValidationState &state,
    const CChainParams &chainparams,
    const CTailstormBlock *pblock,
    CNode *pfrom)
{
    bool result = true;
    CBlockIndex *pindexMostWork = nullptr;

    TxAdmissionPause txlock;
    LOCK(cs_main);
    do
    {
        if (shutdown_threads.load() == true)
        {
            return false;
        }
        if (ShutdownRequested())
        {
            return false;
        }
        pindexMostWork = FindMostWorkChain();
        if (!pindexMostWork)
        {
            return true;
        }

        // Whether we have anything to do at all.
        if (chainActive.Tip() != nullptr)
        {
            if (pindexMostWork->nChainWork <= chainActive.Tip()->nChainWork)
            {
                return true;
            }
        }

        if (!ActivateBestChainStepTailstorm(state, chainparams, pindexMostWork,
                ((pblock) && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullptr)))
        {
            // If we fail to activate a chain because it is bad, send a reject message
            // but keep iterating to reactivate the best known chain.
            int nDoS = 0;
            if (state.IsInvalid(nDoS))
            {
                LOGA("%s(): Chain activation failed, returning to next best choice\n", __func__);
                result = false;

                if (pfrom)
                {
                    pfrom->PushMessage(NetMsgType::REJECT, (std::string)NetMsgType::BLOCK, state.GetRejectCode(),
                        state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), pblock->GetHash());
                    if (nDoS > 0)
                    {
                        dosMan.Misbehaving(pfrom, nDoS);
                    }
                }
            }
            else
            {
                return false;
            }
        }
        else
        {
            // We may have tried to connect an invalid chain prior to connecting a valid one so we need
            // to reset the result to true if we had previously set it to false.
            result = true;
        }

        // Check if the best chain has changed while we were processing blocks.  If so then we need to
        // continue processing the newer chain.  This satisfies a rare edge case where we have initiated
        // a reorg to another chain but before the reorg is complete we end up reorging to a different
        // chain. Set pblock to nullptr here to make sure as we continue we get blocks from disk.
        pindexMostWork = FindMostWorkChain();
        if (!pindexMostWork)
        {
            return false;
        }
        pblock = nullptr;
    } while (pindexMostWork->nChainWork > chainActive.Tip()->nChainWork);
    CheckBlockIndex(chainparams.GetConsensus());

    return result;
}

bool ProcessNewTailstormBlock(CValidationState &state,
    const CChainParams &chainparams,
    CNode *pfrom,
    CTailstormBlock *pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp)
{
    int64_t start = GetStopwatchMicros();
    LOG(THIN, "Processing new block %s from peer %s.\n", pblock->GetHash().ToString(),
        pfrom ? pfrom->GetLogName() : "myself");
    // if (IsChainNearlySyncd() && !fImporting && !fReindex)
    //    SendExpeditedBlock(*pblock, pfrom);

    bool checked = CheckTailstormBlock(*pblock, state);
    if (!checked)
    {
        LOGA("%s(): Invalid tailstorm block: ver:%x time:%d Tx size:%d len:%d\n", __func__, pblock->nVersion, pblock->nTime,
            pblock->vtx.size(), pblock->GetBlockSize());
    }

    // WARNING: cs_main is not locked here throughout but is released and then re-locked during ActivateBestChainTailstorm
    //          If you lock cs_main throughout ProcessNewBlock then you will in effect prevent PV from happening.
    //          TODO: in order to lock cs_main all the way through we must remove the locking from ActivateBestChainTailstorm
    //                but it will require great care because ActivateBestChainTailstorm requires cs_main however it is also
    //                called from other places.  Currently it seems best to leave cs_main here as is.
    {
        LOCK(cs_main);
        uint256 hash = pblock->GetHash();
        bool fRequested = requester.MarkBlockAsReceived(hash, pfrom);
        fRequested |= fForceProcessing;
        if (!checked)
        {
            return error("%s: CheckTailstormBlock FAILED", __func__);
        }

        // Store to disk
        CBlockIndex *pindex = nullptr;
        bool ret = AcceptTailstormBlock(*pblock, state, chainparams, &pindex, fRequested, dbp);
        if (pindex && pfrom)
        {
            const uint256 blockhash = pindex->GetBlockHash();
            mapBlockSource[blockhash] = pfrom->GetId();
        }
        CheckBlockIndex(chainparams.GetConsensus());

        CInv inv(MSG_TAILSTORMBLOCK, hash);
        LOG(NET, "Push inventory B %s\n", inv.ToString());
        if (!ret)
        {
            // BU TODO: if block comes out of order (before its parent) this will happen.  We should cache the block
            // until the parents arrive.

            // If the block was not accepted then reset the fProcessing flag to false.
            requester.BlockRejected(inv, pfrom);

            return error("%s: AcceptBlock FAILED", __func__);
        }
        else
        {
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodes)
            {
                pnode->PushInventory(inv);
            }
        }
    }

    if (!ActivateBestChainTailstorm(state, chainparams, pblock, pfrom))
    {
        if (state.IsInvalid() || state.IsError())
            return error("%s: ActivateBestChainTailstorm failed", __func__);
        else
            return false;
    }

    int64_t end = GetStopwatchMicros();
    if (Logging::LogAcceptCategory(BENCH))
    {
        uint64_t maxTxSizeLocal = 0;
        uint64_t maxVin = 0;
        uint64_t maxVout = 0;
        CTransaction txIn;
        CTransaction txOut;
        CTransaction txLen;

        for (const auto &txref : pblock->vtx)
        {
            if (txref->vin.size() > maxVin)
            {
                maxVin = txref->vin.size();
                txIn = *txref;
            }
            if (txref->vout.size() > maxVout)
            {
                maxVout = txref->vout.size();
                txOut = *txref;
            }
            uint64_t len = ::GetSerializeSize(*txref, SER_NETWORK, PROTOCOL_VERSION);
            if (len > maxTxSizeLocal)
            {
                maxTxSizeLocal = len;
                txLen = *txref;
            }
        }

        LOG(BENCH,
            "ProcessNewTailstormBlock, time: %d, block: %s, len: %d, numTx: %d, maxVin: %llu, maxVout: %llu, maxTx:%llu\n",
            end - start, pblock->GetHash().ToString(), pblock->GetBlockSize(), pblock->vtx.size(), maxVin,
            maxVout, maxTxSizeLocal);
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txIn.GetHash().ToString(), txIn.vin.size(),
            txIn.vout.size(), ::GetSerializeSize(txIn, SER_NETWORK, PROTOCOL_VERSION));
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txOut.GetHash().ToString(), txOut.vin.size(),
            txOut.vout.size(), ::GetSerializeSize(txOut, SER_NETWORK, PROTOCOL_VERSION));
        LOG(BENCH, "tx: %s, vin: %llu, vout: %llu, len: %d\n", txLen.GetHash().ToString(), txLen.vin.size(),
            txLen.vout.size(), ::GetSerializeSize(txLen, SER_NETWORK, PROTOCOL_VERSION));
    }

    LOCK(cs_blockvalidationtime);
    nBlockValidationTime << (end - start);
    return true;
}
