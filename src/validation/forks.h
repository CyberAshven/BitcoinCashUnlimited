// Copyright (c) 2018-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_FORKS_H
#define BITCOIN_FORKS_H

#include "amount.h"
#include "arith_uint256.h"
#include "chain.h"
#include "consensus/params.h"
#include "tweak.h"
#include "univalue/include/univalue.h"

#include <vector>

class CValidationState;
class CBlock;
class CTransaction;
class CBlockIndex;
class CScript;
class CTxMemPoolEntry;

// Return true if this transaction can only be committed post-fork
bool IsTxUAHFOnly(const CTxMemPoolEntry &tx);

// It is not possible to provably determine whether an arbitrary script signs using the old or new sighash type
// without executing the previous output and input scripts.  But we can make a good guess by assuming that
// these are standard scripts.
bool IsTxProbablyNewSigHash(const CTransaction &tx);

/** Test if Nov 15th 2020 fork has activated */
bool IsMay2021Enabled(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip);

/** Check if the next will be the first block where the new set of rules will be enforced */
bool IsMay2021Next(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip);
#endif
