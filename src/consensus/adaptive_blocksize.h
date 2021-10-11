// Copyright (c) 2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ADAPTIVE_BLOCKSIZE_H
#define ADAPTIVE_BLOCKSIZE_H

#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "uint256.h"

/** Return the next maximum block size allowed */
uint64_t CalculateNextMaxBlockSize(CBlockIndex *pindexPrev, uint64_t nBlockSize);

/** Return the max sigchecks allowed for a specified block size */
uint64_t GetMaxBlockSigChecks(uint64_t nBlockSize);

/** Caculated the median value from a vector of values */
uint64_t CalculateMedian(std::vector<uint64_t> &vData);

#endif
