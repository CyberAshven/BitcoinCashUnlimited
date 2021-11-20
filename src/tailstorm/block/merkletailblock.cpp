// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "merkletailblock.h"
#include "consensus/consensus.h"
#include "hashwrapper.h"
#include "utilstrencodings.h"

using namespace std;

CMerkleTailBlock::CMerkleTailBlock(const CBlock &block, const std::set<uint256> &txids)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    // TODO: ptschip -> clearly we need to be able to decode the subblocks
    //                  from the blocks. We'll have to re-instate that feature
    //                  once we get testing to work better.
    //  for (const auto subblock : block.vdag)
    //   {
    //      subblocks.push_back(CMerkleSubBlock(*subblock, txids));
    //   }
}
