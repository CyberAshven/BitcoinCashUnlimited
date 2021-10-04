// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_SUBBLOCK_VALIDATION_H
#define BITCOIN_TAILSTORM_SUBBLOCK_VALIDATION_H

// tailstorm file includes
#include "subblock.h"

// other bitcoin includes
#include "chainparams.h"
#include "consensus/validation.h"
#include "net.h"

class CBlockIndex;

/** Context-independent validity checks */
bool CheckSubBlockHeader(const CSubBlockHeader &block, CValidationState &state, bool fCheckPOW = true);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main
 * held) */
bool TestSubBlockValidity(CValidationState &state,
    const CChainParams &chainparams,
    const CSubBlock &subblock,
    CBlockIndex *pindexPrev,
    bool fCheckPOW = true,
    bool fCheckMerkleRoot = true);

bool ProcessNewSubBlock(const CSubBlock &subblock, CNode *pfrom);

#endif
