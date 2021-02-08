// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCKRELAY_COMPACTRELAY_H
#define BITCOIN_TAILSTORM_BLOCKRELAY_COMPACTRELAY_H

// tailstorm file includes
#include "compactblock.h"
#include "graphene.h"

// other bitcoin includes
#include "sync.h"
#include "uint256.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

typedef int NodeId;

std::shared_ptr<BobCompactBlock> SetCompactBlockToReconstruct(CNode *pfrom, const BobCompactBlock &hash);
std::shared_ptr<BobCompactBlock> GetCompactBlockToReconstruct(CNode *pfrom, const uint256 &hash);
void ClearCompactBlockToReconstruct(NodeId id, const uint256 &hash);

#endif
