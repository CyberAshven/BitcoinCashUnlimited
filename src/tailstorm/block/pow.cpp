// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// tailstorm file includes
#include "pow.h"
#include "tailstorm/dag.h"

// other bitcoin includes
#include "net.h"
#include "key.h"
#include "uint256.h"
#include "crypto/sha256.h"

static uint256 sha256(uint256 data)
{
    uint256 ret;
    CSHA256 sha;
    sha.Write(data.begin(), 256 / 8);
    sha.Finalize(ret.begin());
    return ret;
}

bool CheckTailstormPoW(const CBlockHeader &header, const Consensus::Params &params, uint8_t k)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (k == 0)
        return true;

    if (header.subblockNTxMap.size() != k)
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

    // check that all subblock hashes are below the target
    for (auto &iter : header.subblockNTxMap)
    {
        uint256 hash = iter.first;
        if (params.powAlgorithm == 1)
        {
            // This algorithm uses the hash as a priv key to sign sha256(hash) using deterministic k.
            // This means that any hardware optimization will need to implement signature generation.
            // What we really want is signature validation to be implemented in hardware, so more thought needs to
            // happen.
            uint256 h1 = sha256(hash);
            CKey key; // Use hash as a private key
            key.Set(hash.begin(), hash.end(), false);
            if (!key.IsValid())
                return false; // If we can't POW fails
            std::vector<uint8_t> vchSig;
            if (!key.SignSchnorr(h1, vchSig))
                return false; // Sign sha256(hash) with hash

            // sha256 the signed data to get back to 32 bytes
            CSHA256 sha;
            sha.Write(&vchSig[0], vchSig.size());
            sha.Finalize(hash.begin());
        }
        if (UintToArith256(hash) > bnTarget)
        {
                return false;
        }
    }
    return true;
}
