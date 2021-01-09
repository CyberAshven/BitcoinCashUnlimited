// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTXO_COIN_H
#define BITCOIN_UTXO_COIN_H

#include "compressor.h"
#include "memusage.h"
#include "primitives/transaction.h"
#include "serialize.h"

/**
 * A UTXO entry.
 *
 * Serialized format:
 * - VARINT((coinbase ? 1 : 0) | (height << 1))
 * - the non-spent CTxOut (via CTxOutCompressor)
 */
class Coin
{
public:
    //! unspent transaction output
    CTxOut out;

    //! whether containing transaction was a coinbase
    unsigned int fCoinBase : 1;

    //! at which height this containing transaction was included in the active block chain
    uint32_t nHeight : 31;

    //! construct a Coin from a CTxOut and height/coinbase information.
    Coin(CTxOut &&outIn, int nHeightIn, bool fCoinBaseIn)
        : out(std::move(outIn)), fCoinBase(fCoinBaseIn), nHeight(nHeightIn)
    {
    }
    Coin(const CTxOut &outIn, int nHeightIn, bool fCoinBaseIn) : out(outIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn)
    {
    }

    //! equality test
    friend bool operator==(const Coin &a, const Coin &b)
    {
        // Empty Coin objects are always equal.
        if (a.IsSpent() && b.IsSpent())
            return true;
        return a.fCoinBase == b.fCoinBase && a.nHeight == b.nHeight && a.out == b.out;
    }

    void Clear()
    {
        out.SetNull();
        fCoinBase = false;
        nHeight = 0;
    }

    //! empty constructor
    Coin() : fCoinBase(false), nHeight(0) {}
    bool IsCoinBase() const { return fCoinBase; }

    template <typename Stream>
    void Serialize(Stream &s) const
    {
        assert(!IsSpent());
        uint32_t code = nHeight * 2 + fCoinBase;
        ::Serialize(s, VARINT(code));
        ::Serialize(s, CTxOutCompressor(REF(out)));
    }

    template <typename Stream>
    void Unserialize(Stream &s)
    {
        uint32_t code = 0;
        ::Unserialize(s, VARINT(code));
        nHeight = code >> 1;
        fCoinBase = code & 1;
        ::Unserialize(s, REF(CTxOutCompressor(out)));
    }

    bool IsSpent() const { return out.IsNull(); }
    size_t DynamicMemoryUsage() const { return memusage::DynamicUsage(out.scriptPubKey); }
};

static const Coin emptyCoin;
static const Coin coinEmpty;

#endif // BITCOIN_UTXO_COIN_H
