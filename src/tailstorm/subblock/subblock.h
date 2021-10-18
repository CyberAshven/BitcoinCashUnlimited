// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_SUBBLOCK_SUBBLOCK_H
#define BITCOIN_TAILSTORM_SUBBLOCK_SUBBLOCK_H

#include "primitives/transaction.h"
#include "serialize.h"
#include "uint256.h"
#include "util.h"

const uint32_t SUBBLOCK_BASE_VERSION = 0x20000000;

class CSubBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION = SUBBLOCK_BASE_VERSION;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CSubBlockHeader() { SetNull(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
    }

    friend bool operator<(const CSubBlockHeader &a, const CSubBlockHeader &b)
    {
        return a.GetHash() < b.GetHash();
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const { return (nBits == 0); }
    uint256 GetHash() const;

    int64_t GetBlockTime() const { return (int64_t)nTime; }
};

class CSubBlock : public CSubBlockHeader
{
public:
    // Xpress Validation: (memory only)
    //! Orphans, or Missing transactions that have been re-requested, are stored here.
    std::set<uint256> setUnVerifiedTxns;

    std::vector<CTransactionRef> vtx;
    bool fXVal;

    CSubBlock() { SetNull(); }

    CSubBlock(const CSubBlockHeader &header)
    {
        SetNull();
        *((CSubBlockHeader *)this) = header;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CSubBlockHeader *)this);
        READWRITE(vtx);
    }

    template <typename Stream>
    CSubBlock(deserialize_type, Stream &s)
    {
        Unserialize(s);
    }

    uint64_t GetBlockSize() const;

    void SetNull();

    bool IsNull() const;

    CSubBlockHeader GetBlockHeader() const;

    std::string ToString() const;

    std::set<uint256> GetAncestorHashes() const;

    std::vector<uint256> GetTxHashes() const;
};

typedef std::shared_ptr<CSubBlock> CSubBlockRef;

#endif
