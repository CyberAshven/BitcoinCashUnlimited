// Copyright (c) 2019-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txlookup.h"
#include "primitives/block.h"
#include "uint256.h"

#include <algorithm>


static int64_t slow_pos_lookup(const CBlock &block, const uint256 &hash)
{
    for (size_t i = 0; i < block.vtx.size(); ++i)
    {
        if (block.vtx[i]->GetHash() == hash)
        {
            return i;
        }
    }
    return TX_NOT_FOUND;
}

static int64_t ctor_pos_lookup(const CBlock &block, const uint256 &hash)
{
    // Coinbase is not sorted and thus needs special treatment
    if (block.vtx[0]->GetHash() == hash)
    {
        return 0;
    }

    auto compare = [](auto &blocktx, const uint256 &lookuptx) { return blocktx->GetHash() < lookuptx; };

    auto it = std::lower_bound(begin(block.vtx) + 1, end(block.vtx), hash, compare);

    if (it == end(block.vtx))
    {
        return TX_NOT_FOUND;
    }
    return std::distance(begin(block.vtx), it);
}


/// Finds the position of a transaction in a block.
/// \param ctor Optimized lookup if it's known that block has CTOR ordering
/// \return
int64_t FindTxPosition(const CBlock &block, const uint256 &txhash, bool ctor_optimized)
{
    if (block.vtx.size() == 0)
    {
        // invalid block
        return TX_NOT_FOUND;
    }
    // TODO: ptship - research as to why ctor_pos_lookup is sometimes failing.
    //                Temporariliy call only slow_pos_lookup until this can be fixed.
    //                This bug gets triggered in rawtransaction.py
    return ctor_optimized ? slow_pos_lookup(block, txhash) : slow_pos_lookup(block, txhash);
}
