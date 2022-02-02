// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include "chain.h"
#include "script/interpreter.h"
#include "tweak.h"
#include "uint256.h"

extern CChain chainActive;
extern CTweak<uint64_t> maxSigChecks;
extern CTweak<uint64_t> maxAllowedNetMessage;
extern CTweak<uint64_t> nextMaxBlockSize;

static const unsigned int ONE_MEGABYTE = 1000000;

/** Adaptive block size params */
static const uint64_t DEFAULT_NEXT_MAX_BLOCK_SIZE = 100000; // 100KB
static const uint64_t SHORT_BLOCK_WINDOW = 12960 * 5; // 90 days of blocks with 2 minute block intervals
static const uint64_t LONG_BLOCK_WINDOW = 52550 * 5; // 365 days of blocks with 2 minute block intervals
static const uint64_t SHORT_BLOCK_WINDOW_REGTEST = 150; // used for testing only!
static const uint64_t LONG_BLOCK_WINDOW_REGTEST = 300; // used for testing only!
static const uint64_t BLOCK_SIZE_MULTIPLIER = 10;

/** Default for -blockmaxsize and -blockminsize, which control the range of sizes the mining code will create **/
// this is now set in chain params
static const unsigned int DEFAULT_MAX_BLOCK_SIZE_REGTEST = 8 * ONE_MEGABYTE;
static const unsigned int DEFAULT_MAX_BLOCK_SIZE = 1000 * ONE_MEGABYTE;
static const unsigned int DEFAULT_MAX_BLOCK_SIZE_TESTNET4 = 2 * ONE_MEGABYTE;
static const unsigned int DEFAULT_MAX_BLOCK_SIZE_SCALENET = 256 * ONE_MEGABYTE;

/** The maximum allowed number of signature check operations in a 1MB block (network rule), and the suggested max sigops
 * per (MB rounded up) in blocks > 1MB. */
static const unsigned int MAX_BLOCK_SIGOPS_PER_MB = 20000;
static const unsigned int MAX_TX_SIGOPS_COUNT = 20000;
static const unsigned int MAX_TX_SIGCHECK_COUNT = 3000;
/** The maximum suggested length of a transaction */
static const unsigned int DEFAULT_LARGEST_TRANSACTION = ONE_MEGABYTE;
/** The minimum allowed size for a transaction, in bytes */
static const unsigned int MIN_TX_SIZE = 65;

/** This is the default max bloom filter size allowed on the bitcoin network.  In Bitcoin Unlimited we have the ability
 *  to communicate to our peer what max bloom filter size we will accept but still observe this value as a default.
 */
static const unsigned int SMALLEST_MAX_BLOOM_FILTER_SIZE = 36000; // bytes

/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
/* clang-format off */
static const uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH |
                                                      SCRIPT_VERIFY_STRICTENC |
                                                      SCRIPT_ENABLE_SIGHASH_FORKID |
                                                      SCRIPT_VERIFY_LOW_S |
                                                      SCRIPT_VERIFY_NULLFAIL |
                                                      SCRIPT_VERIFY_MINIMALDATA |
                                                      SCRIPT_ENABLE_SCHNORR_MULTISIG;
/* clang-format on */

/** Number of sigops to reserve for coinbase transaction */
static const uint16_t COINBASE_RESERVED_SIGOPS = 100;

/**
 * The ratio between the maximum allowable block size and the maximum allowable
 * SigChecks (executed signature check operations) in the block, or in other words, how
 * many block bytes per sigcheck. (network rule).
 */
static const uint16_t BLOCK_SIGCHECKS_RATIO = 141;

/** Compute the maximum sigops allowed in a block given the block size. */
inline uint64_t GetMaxBlockSigOpsCount(uint64_t nBlockSize)
{
    auto nMbRoundedUp = 1 + ((nBlockSize - 1) / 1000000);
    return nMbRoundedUp * MAX_BLOCK_SIGOPS_PER_MB;
}

/**
 * Compute the maximum number of sigchecks that can be contained in a block
 * given the MAXIMUM block size as parameter. The maximum sigchecks scale
 * linearly with the maximum block size and do not depend on the actual
 * block size. The returned value is rounded down (there are no fractional
 * sigchecks so the fractional part is meaningless).
 */
inline uint64_t GetMaxBlockSigChecks(uint64_t nBlockSize)
{
    static_assert(
        DEFAULT_NEXT_MAX_BLOCK_SIZE / BLOCK_SIGCHECKS_RATIO >= COINBASE_RESERVED_SIGOPS, "enough sigops for coinbase");

    if (maxSigChecks.Value() > 0)
        return maxSigChecks.Value();
    if (!nextMaxBlockSize.Value())
        assert(nBlockSize >= DEFAULT_NEXT_MAX_BLOCK_SIZE);

    return nBlockSize / BLOCK_SIGCHECKS_RATIO;
}

/** Flags for nSequence and nLockTime locks */
enum
{
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

// Max allowed message assumes that the next block size will be
// the largest message plus 1MB of additional padding.
inline uint64_t GetMaxAllowedNetMessage()
{
    // Used in testing only!
    if (maxAllowedNetMessage.Value())
        return maxAllowedNetMessage.Value();

    // Return the max net message value based on the next
    // expected max block size plus some additional padding
    uint64_t nMaxSize = 0;
    CBlockIndex *tip = chainActive.Tip();
    if (tip)
        nMaxSize = tip->GetNextMaxBlockSize();

    return nMaxSize + ONE_MEGABYTE;
}
#endif // BITCOIN_CONSENSUS_CONSENSUS_H
