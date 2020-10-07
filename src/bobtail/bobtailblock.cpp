#include "miner_common.h"
#include "bobtailblock.h"
#include "rank_items.h"

#include <cmath>
#include <numeric>
#include <unordered_map>

void CBobtailBlock::UpdateTxLists()
{
    // account for all txs in all subblocks in dag
    std::set<CTransactionRef> allTxRefs;
    for (auto sbref : vdag)
    {
        for (auto txRef : sbref->vtx)
        {
            allTxRefs.insert(txRef);
        }
    }

    // insert unique txs (first index reserved for coinbase)
    vtx.resize(allTxRefs.size() + 1);
    uint64_t idx = 1;
    for (auto txRef: allTxRefs)
    {
        vtx[idx] = txRef;
        idx++;
    }
    std::sort(vtx.begin() + 1, vtx.end(), NumericallyLessTxHashComparator());

    std::vector<int> idxs(vtx.size());
    std::iota (std::begin(idxs), std::end(idxs), 0);

    // populate index map
    std::unordered_map<CTransactionRef, uint64_t> txRefToIndex;
    for (uint64_t i=0; i < vtx.size(); i++)
    {
        txRefToIndex[vtx[i]] = i;
    }

    // encode each subblock tx list
    uint8_t nBitsPerItem = ceil(log2(vtx.size()));
    for (auto sbref : vdag)
    {
        std::vector<uint64_t> subIdxList;
        for (auto txRef : sbref->vtx)
        {
            subIdxList.push_back(txRefToIndex[txRef]);
        }
        std::vector<uint8_t> encoded = EncodeRank(subIdxList, nBitsPerItem);
        std::copy(encoded.begin(), encoded.end(), std::inserter(dagEncodingMap[sbref], dagEncodingMap[sbref].end()));
    }
}

std::map<CSubBlockRef, std::vector<CTransactionRef>> CBobtailBlock::DecodeTxLists()
{
    uint8_t nBitsPerItem = ceil(log2(vtx.size()));

    // populate index map
    std::unordered_map<uint64_t, CTransactionRef> indexToTxRef;
    for (uint64_t i=0; i < vtx.size(); i++)
    {
        indexToTxRef[i] = vtx[i];
    }

    // retrieve tranaction refs for each subblock
    std::map<CSubBlockRef, std::vector<CTransactionRef>> subblockTxLists;
    for (auto &kv : dagEncodingMap)
    {
        std::vector<uint8_t> encoded(kv.second.begin(), kv.second.end());
        for (auto idx : DecodeRank(encoded, vtx.size(), nBitsPerItem))
        {
            if (idx >= vtx.size())
                throw std::runtime_error("Subblock tx index beyond length of vtx. Did you call UpdateTxLists first?");

            subblockTxLists[kv.first].push_back(indexToTxRef[idx]);
        }
    }

    return subblockTxLists;
}
