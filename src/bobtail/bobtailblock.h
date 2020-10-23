// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOBTAIL_BOBTAILBLOCK_H
#define BITCOIN_BOBTAIL_BOBTAILBLOCK_H

#include "hashwrapper.h"
#include "primitives/block.h"
#include "subblock.h"

class CBobtailBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION = BASE_VERSION;
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    int64_t nTime;
    uint32_t nBits;
    std::vector<uint256> subblockHashes;

    CBobtailBlockHeader() { SetNull(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(subblockHashes);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        subblockHashes.clear();
    }

    bool IsNull() const { return (nBits == 0); }
    uint256 GetHash() const { return SerializeHash(*this); }
    int64_t GetBlockTime() const { return nTime; }
};

class CBobtailBlock : public CBobtailBlockHeader
{
public:
    // no network
    std::vector<CTransactionRef> vtx;

    // memory only
    std::vector<std::shared_ptr<CSubBlock>> vdag;
    std::map<std::shared_ptr<CSubBlock>, std::set<unsigned char>> dagEncodingMap;

public:
    void UpdateTxLists();
    std::map<CSubBlockRef, std::vector<CTransactionRef>> DecodeTxLists();
};

typedef std::shared_ptr<CBobtailBlock> CBobtailBlockRef;

class CBobtailBlockDisk : public CBobtailBlock
{
public:
    std::vector<CBlockHeader> vsubblock_headers;
public:
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(vsubblock_headers);
        READWRITE(dagEncodingMap);
        READWRITE(vtx);
    }
    void PopulateSubblockHeaders()
    {
        for (const auto &subblock : vdag)
        {
            vsubblock_headers.emplace_back(std::move(subblock->GetBlockHeader()));
        }
    }
};

#endif
