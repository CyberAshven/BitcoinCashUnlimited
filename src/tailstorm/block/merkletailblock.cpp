// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/consensus.h"
#include "hashwrapper.h"
#include "merkletailblock.h"
#include "utilstrencodings.h"

using namespace std;

CMerkleTailBlock::CMerkleTailBlock(const CTailstormBlock &block, const std::set<uint256> &txids)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (const auto subblock : block.vdag)
    {
        subblocks.push_back(CMerkleSubBlock(*subblock, txids));
    }
}
