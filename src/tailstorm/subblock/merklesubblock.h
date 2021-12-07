// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_SUBBLOCK_MERKLESUBBLOCK_H
#define BITCOIN_TAILSTORM_SUBBLOCK_MERKLESUBBLOCK_H

#include "bloom.h"
#include "merkleblock.h"
#include "primitives/subblock.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>

/**
 * Used to relay blocks as header + vector<merkle branch>
 * to filtered nodes.
 */
class CMerkleSubBlock
{
public:
    /** Public only for unit testing */
    CSubBlockHeader header;
    CPartialMerkleTree txn;

public:
    /** Public only for unit testing and relay testing (not relayed) */
    std::vector<std::pair<unsigned int, uint256> > vMatchedTxn;

#ifndef ANDROID // limit dependencies
    /**
     * Create from a CBlock, filtering transactions according to filter
     * Note that this will call IsRelevantAndUpdate on the filter for each transaction,
     * thus the filter will likely be modified.
     */
    CMerkleSubBlock(const CSubBlock &block, CBloomFilter &filter);
#endif

    /** Create from a CBlock, matching the txids in the set
     */
    CMerkleSubBlock(const CSubBlock &block, const std::set<uint256> &txids);

    CMerkleSubBlock() {}
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(txn);
    }
};

#endif // BITCOIN_TAILSTORM_SUBBLOCK_MERKLEBLOCK_H
