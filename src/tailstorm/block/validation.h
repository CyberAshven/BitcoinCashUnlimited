// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCK_VALIDATION_H
#define BITCOIN_TAILSTORM_BLOCK_VALIDATION_H

// tailstorm file includes
#include "block.h"

// other bitcoin includes
#include "chainparams.h"
#include "consensus/validation.h"
//#include "parallel.h"
#include "txdebugger.h"
#include "txmempool.h"
#include "validation/forks.h"
#include "validation/validation.h"
#include "versionbits.h"

class CNode;

bool InitTailstormBlockIndex(const CChainParams &chainparams);

bool CheckTailstormBlockHeader(const CTailstormBlockHeader &header, CValidationState &state);

CBlockIndex *AddToBlockIndex(const CTailstormBlockHeader &block);

bool AcceptTailstormBlockHeader(const CTailstormBlockHeader &block,
    CValidationState &state,
    const CChainParams &chainparams,
    CBlockIndex **ppindex = nullptr);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main
 * held) */
bool TestTailstormBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CTailstormBlock &block,
    CBlockIndex *pindexPrev,
    bool fCheckPOW = true,
    bool fCheckMerkleRoot = true);

bool CheckTailstormBlock(const CTailstormBlock &block, CValidationState &state);

bool ReceivedBlockTransactions(const CTailstormBlock &block,
    CValidationState &state,
    CBlockIndex *pindexNew,
    const CDiskBlockPos &pos);

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectTailstormBlock(const CTailstormBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    const CChainParams &chainparams,
    bool fJustCheck = false);

/** disconnects pIndexDelete, WHICH MUST BE THE CHAIN TIP from the blockchain, unwinding and resubmitting txs to
the blockchain */
bool DisconnectTailstormTip(CValidationState &state,
    const CBlockIndex *pindexDelete,
    const Consensus::Params &consensusParams,
    const bool fRollBack);

DisconnectResult DisconnectTailstormBlock(const CTailstormBlock &block,
    const CBlockIndex *pindex,
    CCoinsViewCache &view);

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during
 * validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state
 * if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly*
 * get feedback on whether pblock is valid, you must also install a CValidationInterface (see validationinterface.h) -
 * this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be
 * penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and
 * whitelisted peers.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */

bool ActivateBestChainTailstorm(CValidationState &state,
    const CChainParams &chainparams,
    const CTailstormBlock *pblock = nullptr,
    CNode *pfrom = nullptr);

bool ProcessNewTailstormBlock(CValidationState &state,
    const CChainParams &chainparams,
    CNode *pfrom,
    CTailstormBlock *pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp);

#endif
