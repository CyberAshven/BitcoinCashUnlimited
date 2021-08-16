// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "tailstorm/dag.h"
#include "tailstorm/pow.h"
#include "validation.h"

// other bitcoin includes
#include "chain.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "main.h" // FormatStateMessage
#include "net.h"
#include "timedata.h"

bool CheckSubBlockHeader(const CSubBlockHeader &block, CValidationState &state, bool fCheckPOW)
{
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus()))
    {
        return state.DoS(50, error("%s(): subblock proof of work failed", __func__), REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
    {
        return state.Invalid(
            error("%s(): block timestamp too far in the future", __func__), REJECT_INVALID, "time-too-new");
    }

    // Check timestamp against prev
    // TODO: this is a contextual check so should not be here.
    // If the subblock is valid, just arriving too late, this can trigger making it seem like a bogus subblock was
    // deliberately sent (which might trigger misbehaving punishment)
    // Even ContextualCheckSubBlock does not make sense for this test because the subblock could be valid
    // *within its context*.
    // The code just doesn't care anymore about this subblock because its too old.  This "do I care" check should be
    // done in higher level code where the context of what too old means is clear.
    if (block.GetBlockTime() <= chainActive.Tip()->GetMedianTimePast())
    {
        return state.Invalid(error("%s: block's timestamp is too early", __func__), REJECT_INVALID, "time-too-old");
    }

    return true;
}

bool CheckSubBlock(const CSubBlock &subblock, CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // Check that the header is valid (particularly PoW).
    if (!CheckSubBlockHeader(subblock, state, fCheckPOW))
    {
        return false;
    }
    // Check the merkle root.
    if (fCheckMerkleRoot)
    {
        bool mutated;
        // this can be reused for subblocks because the merkle root is computed the same way
        uint256 hashMerkleRoot2 = BlockMerkleRoot(subblock, &mutated);
        if (subblock.hashMerkleRoot != hashMerkleRoot2)
        {
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
    }
    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Size limits
    if (subblock.vtx.empty())
    {
        return state.DoS(100, error("CheckSubBlock(): size limits failed"), REJECT_INVALID, "bad-blk-length");
    }
    // First transaction must be proofbase, the rest must not be
    if (subblock.vtx.empty() || !subblock.vtx[0]->IsProofBase())
    {
        return state.DoS(100, error("CheckSubBlock(): first tx is not proofbase"), REJECT_INVALID, "bad-pb-missing");
    }
    for (unsigned int i = 1; i < subblock.vtx.size(); i++)
    {
        if (subblock.vtx[i]->IsProofBase())
        {
            return state.DoS(100, error("CheckSubBlock(): more than one proofbase"), REJECT_INVALID, "bad-pb-multiple");
        }
    }
    for (unsigned int i = 0; i < subblock.vtx.size(); i++)
    {
        if (subblock.vtx[i]->IsCoinBase())
        {
            return state.DoS(100, error("CheckSubBlock(): subblock contains a coinbase"), REJECT_INVALID, "bad-cb-contains");
        }
    }
    // Check transactions
    for (const auto &tx : subblock.vtx)
    {
        if (!CheckTransaction(tx, state))
        {
            return error("CheckSubBlock(): CheckTransaction of %s failed with %s", tx->GetHash().ToString(),
                FormatStateMessage(state));
        }
    }
    return true;
}

bool ContextualCheckSubBlock(const CSubBlock &block, CValidationState &state, CBlockIndex *const pindexPrev)
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
    {
        nLockTimeCutoff = block.GetBlockTime();
    }
    else
    {
        nLockTimeCutoff =
            (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST) ? pindexPrev->GetMedianTimePast() : block.GetBlockTime();
    }
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
        {
            return false;
        }
        nTx++;
        if (tx->GetTxSize() > nLargestTx)
        {
            nLargestTx = tx->GetTxSize();
        }
    }
    return true;
}

bool TestSubBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CSubBlock &subblock,
    CBlockIndex *pindexPrev,
    bool fCheckPOW,
    bool fCheckMerkleRoot)
{
    // TODO : evaluate this lock
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());

    if (!CheckSubBlockHeader(subblock, state, fCheckPOW))
        return false;
    if (!CheckSubBlock(subblock, state, fCheckPOW, fCheckMerkleRoot))
        return false;
    if (!ContextualCheckSubBlock(subblock, state, pindexPrev))
        return false;
    assert(state.IsValid());

    return true;
}


bool ProcessNewSubBlock(const CSubBlock &subblock)
{
    CValidationState state;
    if (CheckSubBlock(subblock, state, true, true))
    {
        if (tailstormDagSet.Insert(subblock))
        {
            auto inv = CInv(MSG_SUBBLOCK, subblock.GetHash());
            LOG(NET, "Push inventory A %s\n", inv.ToString());
            LOCK(cs_vNodes);
            for (CNode *pnode : vNodes)
            {
                pnode->PushInventory(inv);
            }
            return true;
        }
    }
    return false;
}
