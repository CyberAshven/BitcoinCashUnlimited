// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_POW_H
#define BITCOIN_TAILSTORM_POW_H

#include "arith_uint256.h"
#include "block/block.h"
#include "consensus/params.h"

const double KOS_INCLUSION_PROB = 0.99999;
const int DEFAULT_SCALE_FACTOR = 1000;

bool CheckTailstormPoW(const CTailstormBlockHeader &header, const Consensus::Params &params, uint8_t k);

#endif
