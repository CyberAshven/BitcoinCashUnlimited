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
private:
    // memory only
    mutable uint64_t nBlockSize; // Serialized block size in bytes

public:
    // no network
    std::vector<CTransactionRef> vtx;

    // memory only
    std::vector<std::shared_ptr<CSubBlock>> vdag;
    std::map<std::shared_ptr<CSubBlock>, std::set<unsigned char>> dagEncodingMap;

    //! Orphans, or Missing transactions that have been re-requested, are stored here.
    std::set<uint256> setUnVerifiedTxns;

public:
    CBobtailBlockHeader GetBlockHeader()
    {
        CBobtailBlockHeader header;
        header.nVersion = nVersion;
        header.hashPrevBlock = hashPrevBlock;
        header.hashMerkleRoot = hashMerkleRoot;
        header.nTime = nTime;
        header.nBits = nBits;
        header.subblockHashes = subblockHashes;
        return header;
    }

    void SetNull()
    {
        vtx.clear();
        vdag.clear();
        dagEncodingMap.clear();
        CBobtailBlockHeader::SetNull();
    }
    void UpdateTxLists();
    std::map<CSubBlockRef, std::vector<CTransactionRef>> DecodeTxLists();
    // Return the serialized block size in bytes. This is only done once and then the result stored
    // in nBlockSize for future reference, saving unncessary and expensive serializations.
    uint64_t GetBlockSize() const;

    uint64_t GetHeight() const // Returns the block's height as specified in its coinbase transaction
    {
        const CScript &sig = vtx[0]->vin[0].scriptSig;
        int numlen = sig[0];
        if (numlen == OP_0)
            return 0;
        if ((numlen >= OP_1) && (numlen <= OP_16))
            return numlen - OP_1 + 1;
        std::vector<unsigned char> heightScript(numlen);
        copy(sig.begin() + 1, sig.begin() + 1 + numlen, heightScript.begin());
        CScriptNum coinbaseHeight(heightScript, false, numlen);
        return coinbaseHeight.getint();
    }
};

typedef std::shared_ptr<CBobtailBlock> CBobtailBlockRef;

class CBobtailBlockDisk : public CBobtailBlock
{
public:
    std::vector<CSubBlockHeader> vsubblock_headers;
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
