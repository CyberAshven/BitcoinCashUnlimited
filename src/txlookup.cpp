// Copyright (c) 2019-2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txlookup.h"
#include "primitives/block.h"
#include "uint256.h"

#include <algorithm>


static int64_t ctor_pos_lookup(const CBlock &block, const uint256 &tx)
{
    // Coinbase is not sorted and thus needs special treatment
    if (block.vtx[0]->GetHash() == tx)
    {
        return 0;
    }

    auto compare = [](auto &blocktx, const uint256 &lookuptx) { return blocktx->GetHash() < lookuptx; };

    auto it = std::lower_bound(begin(block.vtx) + 1, end(block.vtx), tx, compare);

    if (it == end(block.vtx))
    {
        return TX_NOT_FOUND;
    }
    return std::distance(begin(block.vtx), it);
}


/// Finds the position of a transaction in a block.
/// \return
int64_t FindTxPosition(const CBlock &block, const uint256 &txhash)
{
    if (block.vtx.size() == 0)
    {
        // invalid block
        return TX_NOT_FOUND;
    }
    return ctor_pos_lookup(block, txhash);
}
