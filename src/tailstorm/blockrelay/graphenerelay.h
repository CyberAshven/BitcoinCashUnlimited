// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCKRELAY_GRAPHENERELAY_H
#define BITCOIN_TAILSTORM_BLOCKRELAY_GRAPHENERELAY_H

// tailstorm file includes
#include "compactblock.h"
#include "graphene.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

typedef int NodeId;

void SetSentSBGrapheneBlocks(NodeId id, CSBGrapheneBlock &grapheneBlock);
std::shared_ptr<CSBGrapheneBlock> GetSentSBGrapheneBlocks(NodeId id);
void ClearSentSBGrapheneBlocks(NodeId id);
std::shared_ptr<CSBGrapheneBlock> SetSBGBlockToReconstruct(CNode *pfrom, const CSBGrapheneBlock &hash);
std::shared_ptr<CSBGrapheneBlock> GetSBGBlockToReconstruct(CNode *pfrom, const uint256 &hash);
void ClearSBGBlockToReconstruct(NodeId id, const uint256 &hash);

#endif
