// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCK_MERKLETAILBLOCK_H
#define BITCOIN_TAILSTORM_BLOCK_MERKLETAILBLOCK_H

#include "block.h"
#include "bloom.h"
#include "merkleblock.h"
#include "serialize.h"
#include "tailstorm/subblock/merklesubblock.h"
#include "uint256.h"

#include <vector>

/**
 * Used to relay blocks as header + vector<merkle branch>
 * to filtered nodes.
 */
class CMerkleTailBlock
{
public:
    /** Public only for unit testing */
    CTailstormBlockHeader header;
    std::vector<CMerkleSubBlock> subblocks;

public:
    /** Public only for unit testing and relay testing (not relayed) */
    std::vector<std::pair<unsigned int, uint256> > vMatchedTxn;

    /** Create from a CBlock, matching the txids in the set
     */
    CMerkleTailBlock(const CTailstormBlock &block, const std::set<uint256> &txids);

    CMerkleTailBlock() {}
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(subblocks);
    }
};

#endif // BITCOIN_TAILSTORM_BLOCK_MERKLETAILBLOCK_H
