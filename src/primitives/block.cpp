// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2019 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "arith_uint256.h"
#include "consensus/merkle.h"
#include "crypto/common.h"
#include "hashwrapper.h"
#include "rank_items.h"
#include "streams.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include <cmath>
#include <numeric>
#include <unordered_map>

uint256 SatoshiBlockHeader::GetHash() const { return SerializeHash(*this); }

uint256 CBlockHeader::GetMiningHeaderCommitment() const
{
    CSHA256Writer miniHeader;
    miniHeader << hashPrevBlock << nBits;
    uint256 miniHash = miniHeader.GetHash();

    CSHA256Writer extHeader;
    extHeader << hashAncestor << hashTxFilter << hashMerkleRoot << nTime << ((uint64_t)height) << chainWork << size
              << txCount << maxSize << feePoolAmt << utxoCommitment << minerData << subblockNTxMap;
    uint256 extHash = extHeader.GetHash();

    CSHA256Writer commitment;
    commitment << miniHash << extHash;
    uint256 ret = commitment.GetHash();
    return ret;
}


uint256 GetMiningHash(const uint256 &headerCommitment, const std::vector<unsigned char> &nonce)
{
    CHashWriter ret(SER_GETHASH, 0);
    assert(nonce.size() <= CBlockHeader::MAX_NONCE_SIZE);
    ret << headerCommitment << nonce;
    uint256 r = ret.GetHash();
    return r;
}


uint256 CBlockHeader::GetHash() const
{
    assert(size != 0); // Size must be properly calculated before we can figure out the hash

    // The hash is calculated similarly to the mining header commitment, except that the nonce is included in the
    // extended header.  This means that a very-light client can keep a very small header for uninteresting blocks
    // consisting of the hashPrevBlock, nbits and sha256(extended header).  This data is sufficient to construct
    // the block's identity hash and therefore to prove the chain of blocks and work.
    CSHA256Writer miniHeader;
    miniHeader << hashPrevBlock << nBits;
    CSHA256Writer extHeader;
    extHeader << hashAncestor << hashTxFilter << hashMerkleRoot << nTime << ((uint64_t)height) << chainWork << size
              << txCount << maxSize << feePoolAmt << utxoCommitment << minerData << subblockNTxMap << nonce;

    CSHA256Writer commitment;
    commitment << miniHeader.GetHash() << extHeader.GetHash();
    uint256 ret = commitment.GetHash();
    return ret;
}

uint256 CBlockHeader::GetMiningHash() const
{
    assert(size != 0); // Size must be properly calculated before we can figure out the hash
    return ::GetMiningHash(GetMiningHeaderCommitment(), nonce);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, height=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, txCount=%u "
                   "size=%d(%d), maxSize=%d, feePool=%d, nonce=%s, utxo=%s)\n",
        GetHash().ToString(), height, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, size,
        vtx.size(), maxSize, feePoolAmt, HexStr(nonce), HexStr(utxoCommitment));
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}

std::string CBlock::GetHex() const
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << *this;
    std::string strHex = HexStr(stream.begin(), stream.end());
    return strHex;
}

void CBlock::UpdateHeader()
{
    txCount = vtx.size();
    hashMerkleRoot = BlockMerkleRoot(*this);
    size = CalculateBlockSize();
}

struct TxEncodeHashComparator
{
public:
    bool operator()(const CTransactionRef &a, const CTransactionRef &b) const { return a->GetHash() < b->GetHash(); }
};


arith_uint256 GetWorkForDifficultyBits(uint32_t nBits)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == arith_uint256(0))
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

void CBlock::UpdateTxLists()
{
    // account for all txs in all subblocks in dag
    std::map<uint256, CTransactionRef> allTxRefs;
    for (auto sbref : vdag)
    {
        subblockNTxMap[sbref->GetHash()] = sbref->vtx.size();
        for (auto txRef : sbref->vtx)
        {
            allTxRefs[txRef->GetHash()] = txRef;
        }
    }

    // insert unique txs (first index reserved for coinbase)
    vtx.resize(allTxRefs.size() + 1);
    uint64_t idx = 1;
    for (auto &pair : allTxRefs)
    {
        vtx[idx] = pair.second;
        idx++;
    }
    std::sort(vtx.begin() + 1, vtx.end(), TxEncodeHashComparator());

    std::vector<int> idxs(vtx.size());
    std::iota(std::begin(idxs), std::end(idxs), 0);

    // populate index map
    std::map<uint256, uint64_t> txHashToIndex;
    for (uint64_t i = 0; i < vtx.size(); i++)
    {
        txHashToIndex[vtx[i]->GetHash()] = i;
    }

    uint8_t nBitsPerItem = ceil(log2(vtx.size()));
    for (auto sbref : vdag)
    {
        std::vector<uint64_t> subIdxList;
        for (auto txRef : sbref->vtx)
        {
            subIdxList.push_back(txHashToIndex[txRef->GetHash()]);
        }
        std::vector<uint8_t> encoded = EncodeRank(subIdxList, nBitsPerItem);
        std::vector<uint8_t> encoded_vector(encoded.begin(), encoded.end());
        CSubBlockHeader sbheader = sbref->GetBlockHeader();
        uint256 sbhash = sbref->GetHash();
        dagEncodingMap.emplace(sbhash, std::make_pair(sbheader, std::move(encoded_vector)));
    }
}

std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > CBlock::DecodeTxLists() const
{
    uint8_t nBitsPerItem = ceil(log2(vtx.size()));

    // populate index map
    std::unordered_map<uint64_t, CTransactionRef> indexToTxRef;
    for (uint64_t i = 0; i < vtx.size(); i++)
    {
        indexToTxRef[i] = vtx[i];
    }

    // retrieve tranaction refs for each subblock
    std::map<uint256, std::pair<CSubBlockHeader, std::vector<CTransactionRef> > > subblockTxLists;
    for (auto &kv : dagEncodingMap)
    {
        subblockTxLists[kv.first] = std::make_pair(kv.second.first, std::vector<CTransactionRef>());
        std::vector<uint8_t> encoded(kv.second.second.begin(), kv.second.second.end());
        for (auto idx : DecodeRank(encoded, subblockNTxMap[kv.first], nBitsPerItem))
        {
            if (idx >= vtx.size())
                throw std::runtime_error("Subblock tx index beyond length of vtx. Did you call UpdateTxLists first?");

            subblockTxLists[kv.first].second.push_back(indexToTxRef[idx]);
        }
    }

    return subblockTxLists;
}

uint64_t CBlock::GetBlockSize() const
{
    if (nBlockSize == 0)
        nBlockSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    return nBlockSize;
}

uint64_t CBlock::CalculateBlockSize() const { return GetBlockSize(); }
