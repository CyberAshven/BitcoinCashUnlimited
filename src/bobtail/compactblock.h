// Copyright (c) 2016-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BOBTAIL_COMPACTBLOCK_H
#define BOBTAIL_COMPACTBLOCK_H

#include "bobtail/subblock.h"
#include "bobtail/bobtailblock.h"
#include "bloom.h"
#include "consensus/validation.h"
#include "fastfilter.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "serialize.h"
#include "stat.h"
#include "sync.h"
#include "uint256.h"
#include <atomic>
#include <memory>
#include <vector>

class CTxMemPool;
class CDataStream;
class CNode;

uint64_t BobGetShortID(const uint64_t &shorttxidk0, const uint64_t &shorttxidk1, const uint256 &txhash);


class BobCompactReRequest
{
public:
    // A CompactReRequest subblock
    uint256 blockhash;
    std::set<uint64_t> subBlockHashes;
    mutable uint64_t shorttxidk0, shorttxidk1;

    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockhash);
        READWRITE(subBlockHashes);
        READWRITE(shorttxidk0);
        READWRITE(shorttxidk1);
    }
};

class BobCompactReReqResponse
{
public:
    uint256 blockhash;
    std::vector<CSubBlock> subBlocks;

    BobCompactReReqResponse() {}
    BobCompactReReqResponse(const BobCompactReRequest &req) : blockhash(req.blockhash), subBlocks(req.subBlockHashes.size()) {}
    BobCompactReReqResponse(const CBobtailBlock &block, const std::set<uint64_t> subBlockHashes, uint64_t shorttxidk0, uint64_t shorttxidk1)
    {
        blockhash = block.GetHash();
        if (subBlockHashes.size() > block.vdag.size())
            throw std::invalid_argument("request more transactions than are in a block");

        std::map<uint64_t, CSubBlockRef> blockMap;
        for (auto subblock : block.vdag)
        {
            blockMap[BobGetShortID(shorttxidk0, shorttxidk1, subblock->GetHash())] = subblock;
        }

        for (uint64_t subhash : subBlockHashes)
        {
            auto it = blockMap.find(subhash);
            if (it == blockMap.end())
                throw std::invalid_argument("unknown subblock hash");
            subBlocks.push_back(*it->second);
        }
    }

    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockhash);
        READWRITE(subBlocks);
    }
};

class BobCompactBlock
{
public:
    mutable uint64_t shorttxidk0, shorttxidk1;
    CTransactionRef coinbase;

private:
    // memory only
    mutable uint64_t nSize; // Serialized compact block size in bytes

    uint64_t nonce;
    void FillShortTxIDSelector() const;

public:
    // memory only
    mutable unsigned int nWaitingFor; // Number of subblocks we are still needing to recontruct the block

    // memory only
    std::vector<uint256> vSubHashes256; // List of all 256 bit subblock hashes in the bobtail block
    std::vector<uint64_t> vSubHashes; // List of all 64 bit subblock hashes in the bobtail block
    std::map<uint64_t, CSubBlockRef> mapMissingTx; // Map of subblocks that were re-requested

public:
    static const int SHORTTXIDS_LENGTH = 6;

    std::vector<uint64_t> shorttxids;

    CBlockHeader header;

    // Dummy for deserialization
    BobCompactBlock() : nSize(0), nWaitingFor(0) {}
    BobCompactBlock(const CBobtailBlock &block);

    static bool HandleMessage(CDataStream &vRecv, CNode *pfrom);
    bool process(CNode *pfrom, std::shared_ptr<CBlockThinRelay> pblock);
    CInv GetInv() { return CInv(MSG_BLOCK, header.GetHash()); }
    uint64_t BobGetShortID(const uint256 &txhash) const;

    size_t BlockSubCount() const { return shorttxids.size(); }
    ADD_SERIALIZE_METHODS;

    uint64_t GetSize() const
    {
        if (nSize == 0)
            nSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
        return nSize;
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(header);
        READWRITE(nonce);
        READWRITE(coinbase);

        uint64_t shorttxids_size = (uint64_t)shorttxids.size();
        READWRITE(COMPACTSIZE(shorttxids_size));
        if (ser_action.ForRead())
        {
            size_t i = 0;
            while (shorttxids.size() < shorttxids_size)
            {
                shorttxids.resize(std::min((uint64_t)(1000 + shorttxids.size()), shorttxids_size));
                for (; i < shorttxids.size(); i++)
                {
                    uint32_t lsb = 0;
                    uint16_t msb = 0;
                    READWRITE(lsb);
                    READWRITE(msb);
                    shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
                    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids serialization assumes 6-byte shorttxids");
                }
            }
        }
        else
        {
            for (size_t i = 0; i < shorttxids.size(); i++)
            {
                uint32_t lsb = shorttxids[i] & 0xffffffff;
                uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
                READWRITE(lsb);
                READWRITE(msb);
            }
        }

        if (ser_action.ForRead())
            FillShortTxIDSelector();
    }
};

void validateBobCompactBlock(std::shared_ptr<BobCompactBlock> cmpctblock);


// This struct is so we can obtain a quick summary of stats for UI display purposes
// without needing to take the lock more than once
struct BobCompactBlockQuickStats
{
    // Totals for the lifetime of the node (or since last clear of stats)
    uint64_t nTotalInbound;
    uint64_t nTotalOutbound;
    uint64_t nTotalBandwidthSavings;

    // Last 24-hour averages (or since last clear of stats)
    uint64_t nLast24hInbound;
    double fLast24hInboundCompression;
    uint64_t nLast24hOutbound;
    double fLast24hOutboundCompression;
    uint64_t nLast24hRerequestTx;
    double fLast24hRerequestTxPercent;
    BobCompactBlockQuickStats()
        : nTotalInbound(0), nTotalOutbound(0), nTotalBandwidthSavings(0), nLast24hInbound(0),
          fLast24hInboundCompression(0.0), nLast24hOutbound(0), fLast24hOutboundCompression(0.0),
          nLast24hRerequestTx(0), fLast24hRerequestTxPercent(0.0)
    {
    }
};

// This class stores statistics for compact block derived protocols.
class CBobCompactBlockData
{
private:
    CCriticalSection cs_compactblockstats; // locks everything below this point

    CStatHistory<uint64_t> nOriginalSize;
    CStatHistory<uint64_t> nCompactSize;
    CStatHistory<uint64_t> nInBoundBlocks;
    CStatHistory<uint64_t> nOutBoundBlocks;
    CStatHistory<uint64_t> nMempoolLimiterBytesSaved;
    CStatHistory<uint64_t> nTotalCompactBlockBytes;
    CStatHistory<uint64_t> nTotalFullTxBytes;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapCompactBlocksInBound;
    std::map<int64_t, std::pair<uint64_t, uint64_t> > mapCompactBlocksOutBound;
    std::map<int64_t, double> mapCompactBlockResponseTime;
    std::map<int64_t, double> mapCompactBlockValidationTime;
    std::map<int64_t, int> mapCompactBlocksInBoundReRequestedTx;
    std::map<int64_t, uint64_t> mapCompactBlock;
    std::map<int64_t, uint64_t> mapFullTx;

    /**
        Add new entry to statistics array; also removes old timestamps
        from statistics array using expireStats() below.
        @param [statsMap] a statistics array
        @param [value] the value to insert for the current time
     */
    template <class T>
    void updateStats(std::map<int64_t, T> &statsMap, T value);

    /**
       Expire old statistics in given array (currently after one day).
       Uses getTimeForStats() virtual method for timing. */
    template <class T>
    void expireStats(std::map<int64_t, T> &statsMap);

    /**
      Calculate average of long long values in given map. Return 0 for no entries.
      Expires values before calculation. */
    double average(std::map<int64_t, uint64_t> &map);

    /**
      Calculate total bandwidth savings.
      Requires lock on cs_compactblockstats be held external to this call. */
    double computeTotalBandwidthSavingsInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats);

    /**
      Calculate last 24-hour "compression" percentage
      Requires lock on cs_compactblockstats be held external to this call.

      NOTE: The thinblock and bloom filter maps should be from opposite directions
            For example inbound block map paired wtih outbound bloom filter map

      Side-effect: This method calls expireStats() on mapCompactBlocks

      @param [mapCompactBlocks] a statistics array of inbound/outbound XThin blocks
     */
    double compute24hAverageCompressionInternal(std::map<int64_t, std::pair<uint64_t, uint64_t> > &mapCompactBlocks)
        EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats);

    /**
      Calculate last 24-hour transaction re-request percent for inbound compactblock
      Requires lock on cs_compactblockstats be held external to this call.

      Side-effect: This method calls expireStats() on mapCompactBlocksInBoundReRequestedTx */
    double compute24hInboundRerequestTxPercentInternal() EXCLUSIVE_LOCKS_REQUIRED(cs_compactblockstats);

protected:
    //! Virtual method so it can be overridden for better unit testing
    virtual int64_t getTimeForStats() { return GetTimeMillis(); }
public:
    void UpdateInBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize);
    void UpdateOutBound(uint64_t nCompactBlockSize, uint64_t nOriginalBlockSize);
    void UpdateResponseTime(double nResponseTime);
    void UpdateValidationTime(double nValidationTime);
    void UpdateInBoundReRequestedTx(int nReRequestedTx);
    void UpdateMempoolLimiterBytesSaved(unsigned int nBytesSaved);
    void UpdateCompactBlock(uint64_t nCompactBlockSize);
    void UpdateFullTx(uint64_t nFullTxSize);
    std::string ToString();
    std::string InBoundPercentToString();
    std::string OutBoundPercentToString();
    std::string ResponseTimeToString();
    std::string ValidationTimeToString();
    std::string ReRequestedTxToString();
    std::string MempoolLimiterBytesSavedToString();
    std::string CompactBlockToString();
    std::string FullTxToString();

    /** Reset compact block tracking data */
    void ClearCompactBlockStats();

    void FillCompactBlockQuickStats(BobCompactBlockQuickStats &stats);
};
extern CBobCompactBlockData bobcompactdata; // Singleton class


bool IsBobCompactBlocksEnabled();
void BobSendCompactBlock(const CBobtailBlockRef pblock, CNode *pfrom, const CInv &inv);
bool IsBobCompactBlockValid(CNode *pfrom, std::shared_ptr<BobCompactBlock> compactBlock);

#endif // BOBTAIL_COMPACTBLOCK_H
