// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_TAILSTORM_H
#define BITCOIN_TAILSTORM_TAILSTORM_H

#include "block/miner.h"
#include "block/validation.h"
#include "blockrelay/compactrelay.h"
#include "blockrelay/graphenerelay.h"
#include "subblock/miner.h"
#include "subblock/validation.h"


/**
 * Look up a block and convert it into UniValue/JSON format
 * @param[in] blockindex CBlockIndex*
 * @param[in] txDetails If listTxns is true, True: JSONify the block's tx, False for tx hashes only
 * @param[in] listTxns True list the included txs, False to include the count only
 * throws if the block does not exist
 * returns UniValue block representation
 */
UniValue TailstormBlockToJSON(const CBlockIndex *blockindex, bool txDetails, bool listTxns);

/**
 * Convert a tailstorm block into UniValue/JSON format
 * @param[in] blockindex CBlockIndex*
 * @param[in] txDetails If listTxns is true, True: JSONify the block's tx, False for tx hashes only
 * @param[in] listTxns True list the included txs, False to include the count only
 * returns UniValue block representation
 */
UniValue TailstormBlockToJSON(CTailstormBlockRef block, const CBlockIndex *blockindex, bool txDetails, bool listTxns);

#endif
