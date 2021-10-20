// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "block.h"

// other bitcoin includes
#include "rank_items.h"

#include <cmath>
#include <numeric>
#include <unordered_map>

struct TxEncodeHashComparator
{
public:
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const { return a->GetHash() < b->GetHash(); }
};

void CTailstormBlock::UpdateTxLists()
{
    // account for all txs in all subblocks in dag
    std::map<uint256, CTransactionRef> allTxRefs;
    for (auto sbref : vdag)
    {
        subblockNTxMap[sbref->GetHash()] = sbref->vtx.size();
        for (auto txRef : sbref->vtx)
        {
            allTxRefs[txRef->GetHash()] = txRef;
        }
    }

    // insert unique txs (first index reserved for coinbase)
    vtx.resize(allTxRefs.size() + 1);
    uint64_t idx = 1;
    for (auto &pair : allTxRefs)
    {
        vtx[idx] = pair.second;
        idx++;
    }
    std::sort(vtx.begin() + 1, vtx.end(), TxEncodeHashComparator());

    std::vector<int> idxs(vtx.size());
    std::iota(std::begin(idxs), std::end(idxs), 0);

    // populate index map
    std::map<uint256, uint64_t> txHashToIndex;
    for (uint64_t i = 0; i < vtx.size(); i++)
    {
        txHashToIndex[vtx[i]->GetHash()] = i;
    }

    uint8_t nBitsPerItem = ceil(log2(vtx.size()));
    for (auto sbref : vdag)
    {
        std::vector<uint64_t> subIdxList;
        for (auto txRef : sbref->vtx)
        {
            subIdxList.push_back(txHashToIndex[txRef->GetHash()]);
        }
        std::vector<uint8_t> encoded = EncodeRank(subIdxList, nBitsPerItem);
        std::vector<uint8_t> encoded_vector(encoded.begin(), encoded.end());
        CSubBlockHeader sbheader = sbref->GetBlockHeader();
        uint256 sbhash = sbref->GetHash();
        dagEncodingMap.emplace(sbhash, std::make_pair(sbheader, std::move(encoded_vector)));
    }
}

std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > CTailstormBlock::DecodeTxLists() const
{
    uint8_t nBitsPerItem = ceil(log2(vtx.size()));

    // populate index map
    std::unordered_map<uint64_t, CTransactionRef> indexToTxRef;
    for (uint64_t i = 0; i < vtx.size(); i++)
    {
        indexToTxRef[i] = vtx[i];
    }

    // retrieve tranaction refs for each subblock
    std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > subblockTxLists;
    for (auto &kv : dagEncodingMap)
    {
        subblockTxLists[kv.first] = std::make_pair(kv.second.first, std::vector<CTransactionRef>());
        std::vector<uint8_t> encoded(kv.second.second.begin(), kv.second.second.end());
        for (auto idx : DecodeRank(encoded, subblockNTxMap[kv.first], nBitsPerItem))
        {
            if (idx >= vtx.size())
                throw std::runtime_error("Subblock tx index beyond length of vtx. Did you call UpdateTxLists first?");

            subblockTxLists[kv.first].second.push_back(indexToTxRef[idx]);
        }
    }

    return subblockTxLists;
}

uint64_t CTailstormBlock::GetBlockSize() const
{
    if (nBlockSize == 0)
        nBlockSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    return nBlockSize;
}
