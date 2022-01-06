// Copyright (c) 2018-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "forks.h"
#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "script/interpreter.h"
#include "txmempool.h"
#include "unlimited.h"

#include <inttypes.h>
#include <vector>

bool IsTxProbablyNewSigHash(const CTransaction &tx)
{
    bool oldsighash = false;
    for (auto txin : tx.vin)
    {
        std::vector<unsigned char> data;
        CScript::const_iterator pc(txin.scriptSig.begin());
        opcodetype op;
        if (txin.scriptSig.GetOp(pc, op, data))
        {
            if (!data.empty())
            {
                if (!(data.back() & SIGHASH_FORKID))
                {
                    oldsighash = true;
                }
            }
        }
    }
    return (oldsighash == false);
}

bool IsTxUAHFOnly(const CTxMemPoolEntry &txentry)
{
    if ((txentry.sighashType & SIGHASH_FORKID) || (txentry.sighashType == 0))
    {
        return true;
    }
    return false;
}

// return true for every block from fork block and forward [consensusParams.uahfHeight,+inf)
bool IsMay2021Enabled(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return pindexTip->IsforkActiveOnNextBlock(nMiningForkTime);
}

// This will check if the Fork will be enabled at the next block
// i.e. we are at block x - 1, [consensusParams.uahfHeight-1, +inf]
// state fork: enabled or activated
bool IsMay2021Next(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return pindexTip->forkAtNextBlock(nMiningForkTime);
}
