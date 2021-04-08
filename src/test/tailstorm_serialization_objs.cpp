#include "bloom.h"
#include "consensus/merkle.h"
#include "streams.h"
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

    // Write to file
    std::ofstream outfile;
    outfile.open ("/tmp/generate_merkle_block_hex.dat");
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

    // Write to file
    std::ofstream outfile;
    outfile.open ("/tmp/generate_merkle_subblock_hex.dat");
    outfile << hexStr;
    outfile.close();
}

BOOST_AUTO_TEST_SUITE_END()
