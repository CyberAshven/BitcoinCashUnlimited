// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TAILSTORM_BLOCK_BLOCK_H
#define BITCOIN_TAILSTORM_BLOCK_BLOCK_H

// tailstorm file includes
#include "tailstorm/subblock/subblock.h"

// other bitcoin includes
#include "hashwrapper.h"

const uint32_t TAILSTORM_BASE_VERSION = 0x20000000;

class CTailstormBlockHeader
{
public:
    // header
    static const int32_t CURRENT_VERSION = TAILSTORM_BASE_VERSION;
    // GAS TODO: Verify that time is deterministically derived from subblocks (how? maybe max)
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    // GAS TODO: Verify that time is deterministically derived from subblock time (max)
    int64_t nTime;
    uint32_t nBits;
    // GAS TODO: redundant with subblockNTxMap, remove
    std::set<uint256> subblockHashes;
    std::map<uint256, uint32_t> subblockNTxMap;

    CTailstormBlockHeader() { SetNull(); }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        // GAS TODO sort these before hash serialization to prevent malleability
        // add validation check to prove they are sorted
        READWRITE(subblockHashes);
        // GAS TODO sort these before hash serialization to prevent malleability
        // add validation check to prove they are sorted
        READWRITE(subblockNTxMap);
    }

    int GetSubblockHashes(std::set<uint256>& out)
    {
        int ret = 0;
        for (auto const &item : subblockNTxMap)
        {
            out.insert(item.first);
            ret++;
        }
        return ret;
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        subblockHashes.clear();
        subblockNTxMap.clear();
    }

    bool IsNull() const { return (nBits == 0); }
    uint256 GetHash() const { return SerializeHash(*this); }
    int64_t GetBlockTime() const { return nTime; }
};

class CTailstormBlock : public CTailstormBlockHeader
{
private:
    // memory only
    mutable uint64_t nBlockSize=0; // Serialized block size in bytes

public:
    // no network
    std::vector<CTransactionRef> vtx;

    // memory only
    std::vector<std::shared_ptr<CSubBlock>> vdag;
    std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > decodedMap;

    // no network
    std::map<uint256, std::pair<CSubBlockHeader, std::set<uint8_t> > > dagEncodingMap;

    //! Orphans, or Missing transactions that have been re-requested, are stored here.
    std::set<uint256> setUnVerifiedTxns;

public:
    CTailstormBlockHeader GetBlockHeader() const
    {
        CTailstormBlockHeader header;
        header.nVersion = nVersion;
        header.hashPrevBlock = hashPrevBlock;
        header.hashMerkleRoot = hashMerkleRoot;
        header.nTime = nTime;
        header.nBits = nBits;
        header.subblockHashes = subblockHashes;
        header.subblockNTxMap = subblockNTxMap;
        return header;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*(CTailstormBlockHeader *)this);
        READWRITE(dagEncodingMap);
        READWRITE(vtx);
        if (!ser_action.ForRead()) nBlockSize=0;  // Force block size recalculation since block is being overwritten
    }

    void SetNull()
    {
        vtx.clear();
        vdag.clear();
        dagEncodingMap.clear();
        CTailstormBlockHeader::SetNull();
        nBlockSize=0;  // Force block size recalculation
    }
    void UpdateTxLists();
    std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > DecodeTxLists();
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

    bool PopulateVdag()
    {
        bool success = true;
        vdag.clear();
        vdag.resize(subblockHashes.size());
        int i = 0;
        for (auto &hash : subblockHashes)
        {
            CSubBlockRef subblock = std::make_shared<CSubBlock>();
            success &= GetSubBlock(hash, *subblock);
            vdag[i++] = subblock;
        }

        return success;
    }

    bool GetSubBlock(const uint256 &hash, CSubBlock &subblock)
    {
        subblock.SetNull();
        if (decodedMap.empty())
        {
            decodedMap = DecodeTxLists();
        }
        if (subblockHashes.count(hash) != 0)
        {
            for (const auto &entry : decodedMap)
            {
                if (entry.first == hash)
                {
                    subblock.nVersion = entry.second.first.nVersion;
                    subblock.hashPrevBlock = entry.second.first.hashPrevBlock;
                    subblock.hashMerkleRoot = entry.second.first.hashMerkleRoot;
                    subblock.nTime = entry.second.first.nTime;
                    subblock.nBits = entry.second.first.nBits;
                    subblock.nNonce = entry.second.first.nNonce;
                    subblock.vtx = entry.second.second;
                    return true;
                }
            }
            DbgAssert(false, return false); // its in hashes so must be in decodedMap
            return false;
        }
        return false;
    }
};

typedef std::shared_ptr<CTailstormBlock> CTailstormBlockRef;
typedef std::shared_ptr<const CTailstormBlockRef> ConstCTailstormBlockRef;

static inline CTailstormBlockRef MakeTailstormBlockRef() { return std::make_shared<CTailstormBlock>(); }
template <typename Blk>
static inline CTailstormBlockRef MakeTailstormBlockRef(Blk &&blkIn)
{
    return std::make_shared<CTailstormBlock>(std::forward<Blk>(blkIn));
}

#endif
