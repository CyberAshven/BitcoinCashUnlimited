// Copyright (c) 2016-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef Bitcoin_CRankItems_H
#define Bitcoin_CRankItems_H

#include <cstdint>
#include <vector>

const uint8_t WORD_BITS = 8;

std::vector<uint8_t> EncodeRank(std::vector<uint64_t> items, uint16_t nBitsPerItem);

std::vector<uint64_t> DecodeRank(std::vector<uint8_t> encoded, size_t nItems, uint16_t nBitsPerItem);

#endif /* Bitcoin_CRankItems_H */
