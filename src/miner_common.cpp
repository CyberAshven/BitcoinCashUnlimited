// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "miner_common.h"
#include "pow.h"
#include "timedata.h"
#include "unlimited.h"
#include "validation/forks.h"

extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_coinbaseFlags;


