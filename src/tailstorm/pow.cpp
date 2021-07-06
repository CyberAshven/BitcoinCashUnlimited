// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "pow.h"
#include "dag.h"

// other bitcoin includes
#include "net.h"

bool CheckTailstormPoW(const CTailstormBlockHeader &header, const Consensus::Params &params, uint8_t k)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (k == 0)
        return true;

    if (header.subblockHashes.size() != k)
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

    const uint256 target256 = ArithToUint256(bnTarget);
    // check that all subblock hashes are below the target
    for (const uint256 &subhash : header.subblockHashes)
    {
        if (!(subhash < target256))
        {
            return false;
        }
    }
    return true;
}
