// Copyright (c) 2016-2019 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockstorage/blockcache.h"
#include "chainparams.h"
#include "main.h"
#include "miner.h"
#include "primitives/block.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "txmempool.h"
#include "uint256.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <sstream>
#include <string.h>

extern CTweak<bool> enableSubblockCache;

CBlock cache_testblock1()
{
    CDataStream stream(
        ParseHex(
            "2a09b21809314e85a11018b1bc87df11fa82cbfa201e8a0c7576b5fe4066dffaffff7f200000000000000000000000000000000000"
            "00000000000000000000000000000068be98307e8996803aaafb2a77f267f44af8908e0262073dbe49081b7faa4cf95eec2f610200"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030000000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff055200000100ffffffff0100ca9a3b00"
            "000000232102d392a4b72ece58ad9fdaa04c8e2a1606f33038595787db413010a6f570628d2eac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

CBlock cache_testblock2()
{
    CDataStream stream(
        ParseHex(
            "4a96014ff4723adab09735dfcd25006bb5124f6169f1ef65a67f5834d166438bffff7f200000000000000000000000000000000000"
            "00000000000000000000000000000074f382d5e1511759229380f6a8e87a054e37a1759869adb6ef3f2d5569c5c68c54ed2f616400"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030200000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff050164000000ffffffff0100ca9a3b00"
            "000000232103e57c28ba3d768ae9ad05194f972a4b0a4e5e8d9406cb521e871bf90094ef4118ac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

CBlock cache_testblock3()
{
    CDataStream stream(
        ParseHex(
            "56d437b9b3dd0f28fb3223c8a89e43ba471ff6b035c552b26896488a1670a7a3ffff7f200000000000000000000000000000000000"
            "000000000000000000000000000000b94b61e6b6ad030ad02aad875b210cad2caca80ad954c181c6d4c547eb52dbd65fec2f610400"
            "00000000000000000000000000000000000000000000000000000000000000fc000000000000000100000000030000000101000000"
            "010000000000000000000000000000000000000000000000000000000000000000ffffffff055400000100ffffffff0100ca9a3b00"
            "000000232102d392a4b72ece58ad9fdaa04c8e2a1606f33038595787db413010a6f570628d2eac00000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CBlock block;
    stream >> block;
    return block;
};

CSubBlock cache_test_subblock1()
{
    CDataStream stream(
        ParseHex(
            "00000020ce06ef1a6d16fdbe44445f2f2ab582a9f7111ba4df72550dfa039c74527133441f375a3ef45a27d178e389add7260dfdef"
            "7c82716dab7eb588c2383ee37a3932a25c7d61ffff7f20000000000101000000020000000000000000000000000000000000000000"
            "000000000000000000000000ffffffff232102194d7a5bb52f351b56a4811f2cd35fc3860d4888a5b93011bd2e4b4b32fa4c92acff"
            "ffffff889f8e9a09d59fba022ff48520e6e9666a5674f34eb203bd9fa4ef8d43af6eb565a4b15100ffffffff0000000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CSubBlock block;
    stream >> block;
    return block;
};

CSubBlock cache_test_subblock2()
{
    CDataStream stream(
        ParseHex(
            "00000020ce06ef1a6d16fdbe44445f2f2ab582a9f7111ba4df72550dfa039c7452713344199495189cdcf4896bf9853de03d1b159b"
            "1ae6a14bd9a44e8efa2511c474f704a25c7d61ffff7f20010000000101000000020000000000000000000000000000000000000000"
            "000000000000000000000000ffffffff232102194d7a5bb52f351b56a4811f2cd35fc3860d4888a5b93011bd2e4b4b32fa4c92acff"
            "ffffff1ac416682e515710924dd513fafcebfa28526c13d34d4d30736544ea7e831586e6e3a52400ffffffff0000000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CSubBlock block;
    stream >> block;
    return block;
};

CSubBlock cache_test_subblock3()
{
    CDataStream stream(
        ParseHex(
            "00000020ce06ef1a6d16fdbe44445f2f2ab582a9f7111ba4df72550dfa039c7452713344d73c12f3e5dd351b7fc52cf9e4b24cef41"
            "e89663ee5dca71eb1e7d7d7008d55da25c7d61ffff7f20010000000101000000020000000000000000000000000000000000000000"
            "000000000000000000000000ffffffff232102194d7a5bb52f351b56a4811f2cd35fc3860d4888a5b93011bd2e4b4b32fa4c92acff"
            "ffffffb9cbb882aa78ec4189b685fedac83a472ca829013f3eabc523913fb8b5f63b3c974a487500ffffffff0000000000"),
        SER_NETWORK, PROTOCOL_VERSION);
    CSubBlock block;
    stream >> block;
    return block;
};

BOOST_FIXTURE_TEST_SUITE(blockcache_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(cache_tests)
{
    CBlockCache localcache;
    IsChainNearlySyncdSet(false);

    // Create a new block and add it to the block cache
    CBlockRef pNewBlock1 = MakeBlockRef(cache_testblock1());
    localcache.AddBlock(pNewBlock1, 1);

    // Retrieve the block from the cache
    CBlockRef pBlockCache1;
    if (localcache.GetBlock(pNewBlock1->GetHash(), pBlockCache1))
    {
        BOOST_CHECK(pBlockCache1->GetHash() == pNewBlock1->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block1 in blockcache for: ") + HexStr(pNewBlock1->GetHash()));
    }

    // Create a new subblock and try to add itthe block cache. It should not
    // be added because the subblock cache is not on by default.
    CSubBlockRef pSubBlock1 = MakeSubBlockRef(cache_test_subblock1());
    localcache.AddBlock(pSubBlock1, 1);

    // Retrieve the block from the cache
    CSubBlockRef pSubBlockCache1;
    if (localcache.GetBlock(pSubBlock1->GetHash(), pSubBlockCache1))
    {
        throw std::runtime_error(
            std::string("Subblock found when it should not be for: ") + HexStr(pSubBlock1->GetHash()));
    }

    // Turn on the subblock cache and try adding it again.  It should now be found in the cache.
    enableSubblockCache.Set(true);
    localcache.AddBlock(pSubBlock1, 1);
    if (localcache.GetBlock(pSubBlock1->GetHash(), pSubBlockCache1))
    {
        BOOST_CHECK(pSubBlockCache1->GetHash() == pSubBlock1->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find subblock1 in blockcache for: ") + HexStr(pSubBlock1->GetHash()));
    }

    // Create two new blocks and subblocks and add them to the cache
    CBlockRef pNewBlock2 = MakeBlockRef(cache_testblock2());
    localcache.AddBlock(pNewBlock2, 2);
    CBlockRef pNewBlock3 = MakeBlockRef(cache_testblock3());
    localcache.AddBlock(pNewBlock3, 3);
    CSubBlockRef pSubBlock2 = MakeSubBlockRef(cache_test_subblock2());
    localcache.AddBlock(pSubBlock2, 1);
    CSubBlockRef pSubBlock3 = MakeSubBlockRef(cache_test_subblock3());
    localcache.AddBlock(pSubBlock3, 3);

    // Retrieve block2 from the cache
    CBlockRef pBlockCache2;
    if (localcache.GetBlock(pNewBlock2->GetHash(), pBlockCache2))
    {
        BOOST_CHECK(pBlockCache2->GetHash() == pNewBlock2->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block2 in blockcache for ") + HexStr(pNewBlock2->GetHash()));
    }

    // Retrieve block3 from the cache
    CBlockRef pBlockCache3;
    if (localcache.GetBlock(pNewBlock3->GetHash(), pBlockCache3))
    {
        BOOST_CHECK(pBlockCache3->GetHash() == pNewBlock3->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block3 in blockcache for ") + HexStr(pNewBlock3->GetHash()));
    }

    // Retrieve subblock2 from the cache
    CSubBlockRef pSubBlockCache2;
    if (localcache.GetBlock(pSubBlock2->GetHash(), pSubBlockCache2))
    {
        BOOST_CHECK(pSubBlockCache2->GetHash() == pSubBlock2->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find subblock2 in blockcache for ") + HexStr(pSubBlock2->GetHash()));
    }

    // Retrieve subblock3 from the cache
    CSubBlockRef pSubBlockCache3;
    if (localcache.GetBlock(pSubBlock3->GetHash(), pSubBlockCache3))
    {
        BOOST_CHECK(pSubBlockCache3->GetHash() == pSubBlock3->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find subblock3 in blockcache for ") + HexStr(pSubBlock3->GetHash()));
    }

    // Sanity check that all blocks are not the same
    BOOST_CHECK(pBlockCache1->GetHash() != pBlockCache2->GetHash());
    BOOST_CHECK(pBlockCache1->GetHash() != pBlockCache3->GetHash());
    BOOST_CHECK(pBlockCache2->GetHash() != pBlockCache3->GetHash());

    // Sanity check all subblocks are not the same
    BOOST_CHECK(pSubBlockCache1->GetHash() != pSubBlockCache2->GetHash());
    BOOST_CHECK(pSubBlockCache1->GetHash() != pSubBlockCache3->GetHash());
    BOOST_CHECK(pSubBlockCache2->GetHash() != pSubBlockCache3->GetHash());

    // Erase a block and check it is erased
    localcache.EraseBlock(pNewBlock1->GetHash());
    CBlockRef pBlockCacheNull;
    localcache.GetBlock(pNewBlock1->GetHash(), pBlockCacheNull);
    BOOST_CHECK(pBlockCacheNull == nullptr);

    // Erase a subblock and check it is erased
    localcache.EraseBlock(pSubBlock1->GetHash());
    CSubBlockRef pSubBlockCacheNull;
    localcache.GetBlock(pSubBlock1->GetHash(), pSubBlockCacheNull);
    BOOST_CHECK(pSubBlockCacheNull == nullptr);

    // Make sure all other blocks still exist
    if (localcache.GetBlock(pNewBlock2->GetHash(), pBlockCache2))
    {
        BOOST_CHECK(pBlockCache2->GetHash() == pNewBlock2->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block2 in blockcache for ") + HexStr(pNewBlock2->GetHash()));
    }
    if (localcache.GetBlock(pNewBlock3->GetHash(), pBlockCache3))
    {
        BOOST_CHECK(pBlockCache3->GetHash() == pNewBlock3->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find block3 in blockcache for ") + HexStr(pNewBlock3->GetHash()));
    }
    if (localcache.GetBlock(pSubBlock2->GetHash(), pSubBlockCache2))
    {
        BOOST_CHECK(pSubBlockCache2->GetHash() == pSubBlock2->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find subblock2 in blockcache for ") + HexStr(pSubBlock2->GetHash()));
    }
    if (localcache.GetBlock(pSubBlock3->GetHash(), pSubBlockCache3))
    {
        BOOST_CHECK(pSubBlockCache3->GetHash() == pSubBlock3->GetHash());
    }
    else
    {
        throw std::runtime_error(
            std::string("Could not find subblock3 in blockcache for ") + HexStr(pSubBlock3->GetHash()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
