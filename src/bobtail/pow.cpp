// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"
#include "bobtailblock.h"
#include "dag.h"

#include "net.h"

#include <boost/math/distributions/gamma.hpp>

bool CheckBobtailPoW(const CBobtailBlockHeader &header, const Consensus::Params &params, uint8_t k)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (k == 0)
        return true;

    if (header.subblockHashes.size() < k)
        return false;

    bnTarget.SetCompact(header.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow)
    {
        LOG(WB, "Illegal value encountered when decoding target bits=%d\n", header.nBits);
        return false;
    }

    if (bnTarget > UintToArith256(params.powLimit))
    {
        LOG(WB, "Illegal target value bnTarget=%d for pow limit\n", bnTarget.getdouble());
        return false;
    }

    std::vector<uint256> subblockHashes (header.subblockHashes);
    std::sort(subblockHashes.begin(), subblockHashes.end());
    std::vector<arith_uint256> lowestK;
    for (int i=0;i < k-1;i++)
    {
        lowestK.push_back(UintToArith256(subblockHashes[i]));
    }

    return CheckBobtailPoWFromOrderedProofs(lowestK, bnTarget, k);
}

bool CheckBobtailPoWFromOrderedProofs(std::vector<arith_uint256> proofs, arith_uint256 target, uint8_t k)
{
    arith_uint256 average(0);
    arith_uint256 kTarget(k);
    for (auto proof : proofs)
        average += proof;
    average /= kTarget;

    if (average < target)
        return true;

    return false;
}


bool CheckSubBlockPoW(const CSubBlockHeader &header, const Consensus::Params &params, uint8_t k)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;

    bnTarget.SetCompact(header.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow)
    {
        LOG(WB, "Illegal value encountered when decoding target bits=%d\n", header.nBits);
        return false;
    }

    if (bnTarget > UintToArith256(params.powLimit))
    {
        LOG(WB, "Illegal target value bnTarget=%d for pow limit\n", bnTarget.getdouble());
        return false;
    }

    arith_uint256 pow = UintToArith256(header.GetHash());

    return IsBelowKOSThreshold(pow, bnTarget, k);
}

bool IsBelowKOSThreshold(arith_uint256 pow, arith_uint256 target, uint8_t k, int scaleFactor)
{
    if (k == 0)
        return true;

    // Scale everything down as though the target was only scaleFactor
    arith_uint256 scalar = target / arith_uint256(scaleFactor);
    arith_uint256 scaledTarget = arith_uint256(scaleFactor);
    arith_uint256 scaledPow = pow / scalar;

    boost::math::gamma_distribution<> bobtail_gamma(k, scaledTarget.getdouble());

    return cdf(bobtail_gamma, scaledPow.getdouble()) <= KOS_INCLUSION_PROB;
}

uint32_t GetBestK(uint16_t desiredDagNodes, double probability)
{
    uint32_t kLow = 0;
    uint32_t kHigh = std::numeric_limits<uint16_t>::max();

    while (kHigh - kLow > 1)
    {
        uint32_t kMid = kLow + (kHigh-kLow) / 2;
        boost::math::gamma_distribution<> gammaMid(kMid, 1);

        if (quantile(gammaMid, probability) < desiredDagNodes)
            kLow = kMid;
        else
            kHigh = kMid;
    }

    return kLow;
}
