// Copyright (c) 2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/adaptive_blocksize.h"

uint64_t CalculateMedian(std::vector<uint64_t> &vData)
{
    if (!(vData.size() % 2))
        throw std::runtime_error("Data size does not contain an odd number of elements");

    std::sort(vData.begin(), vData.end());
    return *(vData.begin() + ((vData.size() - 1) / 2));
}

static bool CalculateMedianSize(CBlockIndex *pindex, uint64_t nBlockSize, uint64_t nWindow, uint64_t &nMedianSize)
{
    std::vector<uint64_t> vSizes;
    vSizes.push_back(nBlockSize);
    for (uint64_t i = 0; i < nWindow; i++)
    {
        vSizes.push_back(pindex->GetBlockSize());
        if (!pindex->pprev)
        {
            break;
        }
        pindex = pindex->pprev;
    }
    if (vSizes.size() == nWindow + 1)
    {
        nMedianSize = CalculateMedian(vSizes);
        return true;
    }
    return false;
}

uint64_t CalculateNextMaxBlockSize(CBlockIndex *pindexPrev, uint64_t nBlockSize)
{
    uint64_t nBlockSizeMultiplier = Params().GetConsensus().nBlockSizeMultiplier;
    uint64_t nNextMaxBlockSize = DEFAULT_NEXT_MAX_BLOCK_SIZE;

    if (!pindexPrev)
        return nNextMaxBlockSize;

    // Find the median blocksize values for both long and short windows. Whichever median is highest we will use to
    // determine the next max blocksize.
    uint64_t nMedianShortWindow = 0;
    bool fShortWindow =
        CalculateMedianSize(pindexPrev, nBlockSize, Params().GetConsensus().nShortBlockWindow, nMedianShortWindow);
    uint64_t nMedianLongWindow = 0;
    bool fLongWindow =
        CalculateMedianSize(pindexPrev, nBlockSize, Params().GetConsensus().nLongBlockWindow, nMedianLongWindow);

    // In general we will have both the long and short window median values, however during the initial mining
    // of the new chain we may not yet have either the short window or both short and long window median values.
    if (fLongWindow && fShortWindow)
    {
        nNextMaxBlockSize = std::max(nMedianShortWindow, nMedianLongWindow) * nBlockSizeMultiplier;
    }
    else if (fShortWindow)
    {
        nNextMaxBlockSize = nMedianShortWindow * nBlockSizeMultiplier;
    }

    // use the default value if next max size is too small.
    nNextMaxBlockSize = std::max(nNextMaxBlockSize, DEFAULT_NEXT_MAX_BLOCK_SIZE);

    // make sure we are not over the maximum allowed
    nNextMaxBlockSize = std::min(nNextMaxBlockSize, Params().GetConsensus().nDefaultMaxBlockSize);

    return nNextMaxBlockSize;
}
