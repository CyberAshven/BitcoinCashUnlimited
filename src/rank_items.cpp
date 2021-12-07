#include "rank_items.h"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <memory>
#include <vector>

std::vector<uint8_t> EncodeRank(std::vector<uint64_t> items, uint16_t nBitsPerItem)
{
    size_t nItems = items.size();
    size_t nEncodedWords = int(ceil(nBitsPerItem * nItems / float(WORD_BITS)));
    std::vector<uint8_t> encoded(nEncodedWords, 0);

    // form boolean array (low-order first)
    std::unique_ptr<bool[]> bits(new bool[nEncodedWords * WORD_BITS]);
    for (size_t i = 0; i < items.size(); i++)
    {
        uint64_t item = items[i];

        if (ceil(log2(item)) > nBitsPerItem)
            throw std::runtime_error("Not enough bits to uniquely encode items.");

        for (uint16_t j = 0; j < nBitsPerItem; j++)
            bits[j + i * nBitsPerItem] = (item >> j) & 1;
    }

    // encode boolean array
    for (size_t i = 0; i < nEncodedWords; i++)
    {
        encoded[i] = 0;
        for (size_t j = 0; j < WORD_BITS; j++)
            encoded[i] |= bits[j + i * WORD_BITS] << j;
    }

    return encoded;
}

std::vector<uint64_t> DecodeRank(std::vector<uint8_t> encoded, size_t nItems, uint16_t nBitsPerItem)
{
    size_t nEncodedWords = int(ceil(nBitsPerItem * nItems / float(WORD_BITS)));

    // decode into boolean array (low-order first)
    std::unique_ptr<bool[]> bits(new bool[nEncodedWords * WORD_BITS]);

    for (size_t i = 0; i < nEncodedWords; i++)
    {
        uint8_t word = encoded[i];

        for (size_t j = 0; j < WORD_BITS; j++)
            bits[j + i * WORD_BITS] = (word >> j) & 1;
    }

    // convert boolean to item array
    std::vector<uint64_t> items(nItems, 0);
    for (size_t i = 0; i < nItems; i++)
    {
        for (size_t j = 0; j < nBitsPerItem; j++)
            items[i] |= bits[j + i * nBitsPerItem] << j;
    }
    return items;
}
