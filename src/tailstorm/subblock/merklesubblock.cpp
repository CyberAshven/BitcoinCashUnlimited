// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "merklesubblock.h"
#include "consensus/consensus.h"
#include "hashwrapper.h"
#include "utilstrencodings.h"

using namespace std;

#ifndef ANDROID // limit dependencies
CMerkleSubBlock::CMerkleSubBlock(const CSubBlock &block, CBloomFilter &filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (const auto &tx : block.vtx)
    {
        vMatch.push_back(filter.MatchAndInsertOutputs(tx));
    }

    for (size_t i = 0; i < block.vtx.size(); i++)
    {
        const uint256 &hash = block.vtx[i]->GetHash();
        if (!vMatch[i])
        {
            vMatch[i] = filter.MatchInputs(block.vtx[i]);
        }
        if (vMatch[i])
        {
            vMatchedTxn.push_back(make_pair(i, hash));
        }

        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}
#endif

CMerkleSubBlock::CMerkleSubBlock(const CSubBlock &block, const std::set<uint256> &txids)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const uint256 &hash = block.vtx[i]->GetHash();
        if (txids.count(hash))
            vMatch.push_back(true);
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}
