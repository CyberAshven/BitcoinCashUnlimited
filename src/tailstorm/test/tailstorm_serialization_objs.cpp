#include "bloom.h"
#include "consensus/merkle.h"
#include "streams.h"
#include "tailstorm/block/merkletailblock.h"
#include "tailstorm/subblock/merklesubblock.h"
#include "tailstorm/tailstorm.h"
#include "test/test_bitcoin.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <iostream>
#include <string>

#include "merkleblock.h"

BOOST_FIXTURE_TEST_SUITE(tailstorm_serialization_objs, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(generate_merkle_block_hex)
{
    // Set up objects
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.n = 11;
    CTransactionRef tx = std::make_shared<const CTransaction>(mtx);
    filter.insert(tx->GetHash());
    CBlock block;
    block.vtx.push_back(tx);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    CMerkleBlock mb(block, filter);

    // Serialize
    CDataStream ssMerBlk(SER_NETWORK, PROTOCOL_VERSION);
    ssMerBlk << mb;
    std::string hexStr = HexStr(ssMerBlk.begin(), ssMerBlk.end());

    // Deserialize
    CMerkleBlock mb2;
    std::vector<unsigned char> msbData(ParseHex(hexStr));
    CDataStream ssData(msbData, SER_NETWORK, PROTOCOL_VERSION);
    ssData >> mb2;
    BOOST_CHECK(mb2.header == mb.header);
    std::vector<uint256> vMatch;
    std::vector<unsigned int> vnIndex;
    mb2.txn.ExtractMatches(vMatch, vnIndex);
    BOOST_CHECK(vMatch[0] == tx->GetHash());

    // Write to file
    std::ofstream outfile;
    outfile.open("/tmp/generate_merkle_block_hex.dat");
    outfile << hexStr;
    outfile.close();
}

BOOST_AUTO_TEST_CASE(generate_merkle_subblock_hex)
{
    // Set up objects
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.n = 11;
    CTransactionRef tx = std::make_shared<const CTransaction>(mtx);
    filter.insert(tx->GetHash());
    CSubBlockRef subref = std::make_shared<CSubBlock>();
    subref->vtx.push_back(tx);
    subref->hashMerkleRoot = BlockMerkleRoot(*subref);
    CMerkleSubBlock msb(*subref, filter);

    // Serialize
    CDataStream ssMerBlk(SER_NETWORK, PROTOCOL_VERSION);
    ssMerBlk << msb;
    std::string hexStr = HexStr(ssMerBlk.begin(), ssMerBlk.end());

    // Deserialize
    CMerkleSubBlock msb2;
    std::vector<unsigned char> msbData(ParseHex(hexStr));
    CDataStream ssData(msbData, SER_NETWORK, PROTOCOL_VERSION);
    ssData >> msb2;
    BOOST_CHECK(msb2.header.GetHash() == msb.header.GetHash());
    std::vector<uint256> vMatch;
    std::vector<unsigned int> vnIndex;
    msb2.txn.ExtractMatches(vMatch, vnIndex);
    BOOST_CHECK(vMatch[0] == tx->GetHash());

    // Write to file
    std::ofstream outfile;
    outfile.open("/tmp/generate_merkle_subblock_hex.dat");
    outfile << hexStr;
    outfile.close();
}

BOOST_AUTO_TEST_CASE(generate_merkle_tailblock_hex)
{
    /*
        // Set up objects
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout.n = 11;
        CTransactionRef tx = std::make_shared<const CTransaction>(mtx);
        std::set<uint256> txids;
        txids.insert(tx->GetHash());
        CSubBlockRef subref1 = std::make_shared<CSubBlock>();
        subref1->vtx.push_back(tx);
        subref1->hashMerkleRoot = BlockMerkleRoot(*subref1);
        CSubBlockRef subref2 = std::make_shared<CSubBlock>();
        subref2->vtx.push_back(tx);
        subref2->hashMerkleRoot = BlockMerkleRoot(*subref2);
        CTailstormBlock block;
        block.vdag.push_back(subref1);
        block.subblockHashes.emplace(subref1->GetHash());
        block.subblockNTxMap[subref1->GetHash()] = subref1->vtx.size();
        block.vdag.push_back(subref2);
        block.subblockHashes.emplace(subref2->GetHash());
        block.subblockNTxMap[subref2->GetHash()] = subref2->vtx.size();
        block.UpdateTxLists();
        // add coinbase
        block.vtx[0] = std::make_shared<const CTransaction>();
        block.hashMerkleRoot = BlockMerkleRoot(block);
        CMerkleTailBlock mtb(block, txids);

        // Serialize
        CDataStream ssMerBlk(SER_NETWORK, PROTOCOL_VERSION);
        ssMerBlk << mtb;
        std::string hexStr = HexStr(ssMerBlk.begin(), ssMerBlk.end());

        // Deserialize
        CMerkleTailBlock mtb2;
        std::vector<unsigned char> mtbData(ParseHex(hexStr));
        CDataStream ssData(mtbData, SER_NETWORK, PROTOCOL_VERSION);
        ssData >> mtb2;
        BOOST_CHECK(mtb2.header.GetHash() == mtb.header.GetHash());
        std::vector<uint256> vMatch1;
        std::vector<unsigned int> vnIndex1;
        mtb2.subblocks[0].txn.ExtractMatches(vMatch1, vnIndex1);
        BOOST_CHECK(vMatch1[0] == tx->GetHash());
        std::vector<uint256> vMatch2;
        std::vector<unsigned int> vnIndex2;
        mtb2.subblocks[1].txn.ExtractMatches(vMatch2, vnIndex2);
        BOOST_CHECK(vMatch2[0] == tx->GetHash());
        BOOST_CHECK(mtb.header.GetHash() == mtb2.header.GetHash());

        // Write to file
        std::ofstream outfile;
        outfile.open("/tmp/generate_merkle_tailblock_hex.dat");
        outfile << hexStr;
        outfile.close();
    */
}

BOOST_AUTO_TEST_SUITE_END()
