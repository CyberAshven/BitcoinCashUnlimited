// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2021 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "script/standard.h"
#include "txadmission.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/validation.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

extern CTweak<bool> xvalTweak;

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)


// BOOST_CHECK_EXCEPTION predicates to check the specific validation error
class HasReason
{
public:
    HasReason(const std::string &reason) : m_reason(reason) {}
    bool operator()(const std::runtime_error &e) const
    {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };

private:
    const std::string m_reason;
};

bool MiningLoop(const Consensus::Params &cparams,
    uint256 headerCommitment,
    std::vector<unsigned char> &nonce,
    uint32_t nBits,
    unsigned long int tries,
    std::atomic<bool> *abort)
{
    uint64_t count = 0;
    // printf("%s\n", HexStr(nonce).c_str());
    for (uint64_t x = 0; x < 8; x++)
        if (x < nonce.size())
            count = count | (nonce[x] << (x * 8ULL));

    uint64_t nsz = nonce.size();
    while ((tries > 0) && ((abort == nullptr) || (*abort == false)))
    {
        uint256 mhash = ::GetMiningHash(headerCommitment, nonce);
        if (CheckProofOfWork(mhash, nBits, cparams))
        {
            // printf("pow hash: %s\n", mhash.GetHex().c_str());
            return true;
        }
        ++count;
        for (uint64_t x = 0; x < 8; x++)
        {
            if (x < nsz)
            {
                nonce[x] = (count >> (x * 8)) & 255;
            }
            else
            {
                break;
            }
        }
        tries--;
    }
    return false;
}


bool ThreadedMineBlock(int nThreads,
    CBlockHeader &blockHeader,
    unsigned long int tries,
    const Consensus::Params &cparams)
{
    boost::thread_group minerThreads;
    std::vector<std::thread> grp;
    std::atomic<bool> done(false);
    std::mutex lock;

    uint256 headerCommitment = blockHeader.GetMiningHeaderCommitment();
    FastRandomContext insecure_rand;

    for (int i = 0; i < nThreads - 1; i++)
    {
        grp.emplace_back(
            [&](int idx)
            {
                std::vector<unsigned char> tnonce;
                tnonce.resize(5);
                tnonce[4] = idx;
                tnonce[3] = insecure_rand.rand32() & 255;
                bool result = MiningLoop(cparams, headerCommitment, tnonce, blockHeader.nBits, tries, &done);
                {
                    std::lock_guard<std::mutex> guard(lock);
                    if (result == true)
                    {
                        done = true;
                        blockHeader.nonce = tnonce;
                    }
                }
            },
            i);
    }

    for (auto &t : grp)
        t.join();

    return (done == true);
}


static struct
{
    std::string nonceHex;
} blockinfo[] = {
    {"b41700e4ff"},
    {"dce4008bff"},
    {"526200aaff"},
    {"c017006600"},
    {"8e0f01b3ff"},
    {"7f5100f3ff"},
    {"15e1016800"},
    {"a612015000"},
    {"9f89031400"},
    {"a93601dbff"},
    {"8402022b00"},
    {"598d00a1ff"},
    {"a0b3005e00"},
    {"2d78043400"},
    {"c942011d00"},
    {"8471008fff"},
    {"bc0b0194ff"},
    {"055703e3ff"},
    {"153200d6ff"},
    {"fe75006700"},
    {"b2ab00a1ff"},
    {"a2a6002700"},
    {"a363015a00"},
    {"a24b000d00"},
    {"e162012500"},
    {"d0b600c6ff"},
    {"9a72021300"},
    {"b12e00c3ff"},
    {"d8ed000200"},
    {"bcdd027300"},
    {"e3910187ff"},
    {"bd69027400"},
    {"65c503bfff"},
    {"27c3018fff"},
    {"9f9b011a00"},
    {"cfa3000900"},
    {"258e018aff"},
    {"ea77006a00"},
    {"42a900d6ff"},
    {"f7d101b1ff"},
    {"2cf800adff"},
    {"5069003400"},
    {"5a46005300"},
    {"a831004a00"},
    {"0275002300"},
    {"ce91026d00"},
    {"935e00daff"},
    {"0b6700faff"},
    {"da3a004300"},
    {"45e7004300"},
    {"69d8016100"},
    {"7d720090ff"},
    {"ff7d026100"},
    {"16fb01e2ff"},
    {"75a7007900"},
    {"aa84003400"},
    {"0ff1019eff"},
    {"692c006000"},
    {"7ae2009cff"},
    {"6de601a0ff"},
    {"73f802e5ff"},
    {"557b02eaff"},
    {"5b9a009fff"},
    {"6d4a01d5ff"},
    {"6c67006c00"},
    {"e522013c00"},
    {"651901ceff"},
    {"5eb701efff"},
    {"c57300bdff"},
    {"ed28030b00"},
    {"378b01e8ff"},
    {"c9ae0098ff"},
    {"2c1500c0ff"},
    {"7b1f0199ff"},
    {"030801eaff"},
    {"cc3600bfff"},
    {"7f7002caff"},
    {"684b026600"},
    {"ab5b00b5ff"},
    {"b00b000a00"},
    {"37aa0080ff"},
    {"20e1033700"},
    {"b52001a2ff"},
    {"58fb005600"},
    {"fb89024300"},
    {"d121000a00"},
    {"d7bb0095ff"},
    {"f4ce010300"},
    {"bf7f03b9ff"},
    {"654c00b8ff"},
    {"2c97017c00"},
    {"76e50183ff"},
    {"7162000300"},
    {"c83905b6ff"},
    {"c278012300"},
    {"6b5f01c7ff"},
    {"1e7b007900"},
    {"21d8032a00"},
    {"564a01eaff"},
    {"b703022d00"},
    {"c87f01d9ff"},
    {"65d3006400"},
    {"2ca405f9ff"},
    {"ffdd01a6ff"},
    {"544f015d00"},
    {"822800c5ff"},
    {"3e76000300"},
    {"6c7c01dbff"},
    {"4389007800"},
    {"dca2002b00"},
};

CBlockIndex CreateBlockIndex(int nHeight)
{
    CBlockIndex index;
    index.header.height = nHeight;
    index.pprev = chainActive.Tip();
    return index;
}

bool TestSequenceLocks(const CTransaction &tx, int flags)
{
    READLOCK(mempool.cs_txmempool);
    return CheckSequenceLocks(MakeTransactionRef(tx), flags);
}

bool TxIn(uint256 txHash, std::vector<CTransactionRef> &vtx)
{
    for (const auto &tx : vtx)
        if (tx->GetHash() == txHash)
            return true;
    return false;
}

// Test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
// Note that this test assumes blockprioritysize is 0.
void TestPackageSelection(const CChainParams &chainparams, CScript scriptPubKey, std::vector<CTransactionRef> &txFirst)
{
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;
    auto cbAmt = chainparams.GetConsensus().initialSubsidy;

    SetArg("-blockprioritysize", std::to_string(0));
    dMinLimiterTxFee.Set(1.0);
    dMaxLimiterTxFee.Set(1.0);
    excessiveBlockSize = maxGeneratedBlock;
    fCanonicalTxsOrder = false;

    // Test that a medium fee transaction will be selected after a higher fee
    // rate package with a low fee rate parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000;
    // This tx has a low fee: 1000 satoshis
    uint256 hashParentTx = tx.GetHash(); // save this txid for later use
    mempool.addUnchecked(hashParentTx, entry.Fee(1000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a medium fee: 10000 satoshis
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 10000;
    uint256 hashMediumFeeTx = tx.GetHash();
    mempool.addUnchecked(hashMediumFeeTx, entry.Fee(10000).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    // This tx has a high fee, but depends on the first transaction
    tx.vin[0].prevout.hash = hashParentTx;
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000; // 50k satoshi fee
    uint256 hashHighFeeTx = tx.GetHash();
    mempool.addUnchecked(hashHighFeeTx, entry.Fee(50000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // Note the original code requires that the order of tx in the block matches the order tx were selected.
    // This is not necessarily true.  The best we can do is check that all tx were included in the block.
    BOOST_CHECK(pblocktemplate->block.vtx.size() == 4);

    // Test that a package below the min relay fee doesn't get included
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000; // 0 fee
    uint256 hashFreeTx = tx.GetHash();
    mempool.addUnchecked(hashFreeTx, entry.Fee(0).FromTx(tx));
    size_t freeTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

    // Calculate a fee on child transaction that will put the package just
    // below the min relay fee (assuming 1 child tx of the same size).
    CAmount feeToUse = minRelayTxFee.GetFee(2 * freeTxSize) - 1;

    tx.vin[0].prevout.hash = hashFreeTx;
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy - 1000 - 50000 - feeToUse;
    uint256 hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx, entry.Fee(feeToUse).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // Verify that the free tx and the low fee tx didn't get selected
    for (size_t i = 0; i < pblocktemplate->block.vtx.size(); ++i)
    {
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashFreeTx);
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashLowFeeTx);
    }

    // Test that packages above the min relay fee do get included, even if one
    // of the transactions is below the min relay fee
    // Remove the low fee transaction and replace with a higher fee transaction
    std::list<CTransactionRef> dummy;
    mempool.removeRecursive(tx, dummy);
    tx.vout[0].nValue -= 2; // Now we should be just over the min relay fee
    hashLowFeeTx = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx, entry.Fee(feeToUse + 2).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(TxIn(hashFreeTx, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashLowFeeTx, pblocktemplate->block.vtx));

    // Test that transaction selection properly updates ancestor fee
    // calculations as ancestor transactions get included in a block.
    // Add a 0-fee transaction that has 2 outputs.
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vout.resize(2);
    tx.vout[0].nValue = cbAmt - 100000000;
    tx.vout[1].nValue = 100000000; // 1BTC output
    uint256 hashFreeTx2 = tx.GetHash();
    mempool.addUnchecked(hashFreeTx2, entry.Fee(0).SpendsCoinbase(true).FromTx(tx));

    // This tx can't be mined by itself
    tx.vin[0].prevout.hash = hashFreeTx2;
    tx.vout.resize(1);
    feeToUse = minRelayTxFee.GetFee(freeTxSize);
    tx.vout[0].nValue = cbAmt - 100000000 - feeToUse;
    uint256 hashLowFeeTx2 = tx.GetHash();
    mempool.addUnchecked(hashLowFeeTx2, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);

    // Verify that this tx isn't selected.
    for (size_t i = 0; i < pblocktemplate->block.vtx.size(); ++i)
    {
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashFreeTx2);
        BOOST_CHECK(pblocktemplate->block.vtx[i]->GetHash() != hashLowFeeTx2);
    }

    // This tx will be mineable. And will also now allow hashLowFeeTx2 to be
    // mined once hashFreeTx2 and hashHighFeeTx2 are in the block.
    tx.vin[0].prevout.n = 1;
    tx.vout[0].nValue = 100000000 - 10000; // 10k satoshi fee
    uint256 hashHighFeeTx2 = tx.GetHash();
    mempool.addUnchecked(tx.GetHash(), entry.Fee(10000).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    // hashHighFeeTx2 now makes hashFreeTx2 mineable.
    BOOST_CHECK(TxIn(hashFreeTx2, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashHighFeeTx2, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashLowFeeTx2, pblocktemplate->block.vtx));

    // Test CPFP with AGT (ancestor grouped transactions)
    // Add another 0 fee tx to higher fee tx chain. This should also get mined
    // because the total package fees will still be above the minrelaytxfee
    tx.vin[0].prevout.n = 0;
    tx.vin[0].prevout.hash = hashHighFeeTx2;
    feeToUse = 0;
    tx.vout[0].nValue = 100000000 - 10000 - feeToUse; // 0 fee
    uint256 hashFreeTx3 = tx.GetHash();
    mempool.addUnchecked(hashFreeTx3, entry.Fee(feeToUse).SpendsCoinbase(false).FromTx(tx));
    pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);

    // Although hashFreeTx3 is a zero fee it still gets mined before hashLowFeeTx2 which
    // has a higher fee. This is because hashFreeTx3 is part of the ancestor grouping
    // along with hashHighFeeTx2 and hashFreeTx2 and since it's "group" fee is higher
    // than hashLowFeeTx2 then it will get mined first.
    BOOST_CHECK(TxIn(hashFreeTx2, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashHighFeeTx2, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashFreeTx3, pblocktemplate->block.vtx));
    BOOST_CHECK(TxIn(hashLowFeeTx2, pblocktemplate->block.vtx));

    // reset back to ctor
    fCanonicalTxsOrder = true;
}

void GenerateBlocks(const CChainParams &chainparams,
    CScript scriptPubKey,
    uint64_t nStartSize,
    uint64_t nEndSize,
    uint64_t nIncrease)
{
    nTotalPackage = 0;

    // Now generate lots of blocks, increasing the block size on each iteration.
    uint64_t nTotalMine = 0;
    int nBlockCount = 0;
    uint64_t nTotalBlockSize = 0;
    uint64_t nTotalExpectedBlockSize = 0;
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    for (unsigned int i = nStartSize; i <= nEndSize; i += nIncrease)
    {
        nBlockCount++;
        nTotalExpectedBlockSize += i;

        maxGeneratedBlock = i;
        uint64_t nStartMine = GetStopwatchMicros();
        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        nTotalBlockSize += pblocktemplate->block.GetBlockSize();
        nTotalMine += GetStopwatchMicros() - nStartMine;
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block.fExcessive == false);
        BOOST_CHECK(pblocktemplate->block.GetBlockSize() <= maxGeneratedBlock);
        unsigned int blockSize = pblocktemplate->block.GetBlockSize();
        BOOST_CHECK(blockSize <= maxGeneratedBlock);
        printf("%lu %lu:%lu <= %lu\n", (long unsigned int)blockSize,
            (long unsigned int)pblocktemplate->block.GetBlockSize(), pblocktemplate->block.vtx.size(),
            (long unsigned int)maxGeneratedBlock);
    }

    printf("mempool size : %ld\n", mempool.size());
    printf("mempool mapTx size : %ld\n", mempool.mapTx.size());
    printf("Avg Block Size %ld Expected Avg Block Size %ld\n", nTotalBlockSize / nBlockCount,
        nTotalExpectedBlockSize / nBlockCount);
    printf("Block fill ratio %5.2f\n",
        (double)(nTotalBlockSize / nBlockCount) * 100 / (nTotalExpectedBlockSize / nBlockCount));
    printf("Total mining time: %5.2f\n", (double)nTotalMine / 1000000);
    printf("packagetx mining %5.2f\n", (double)nTotalPackage / 1000000);

    mempool.clear();
}


// A peformance test suite for ancestor feerate transaction selection.
// Implemented as an additional function, rather than a separate test case,
// to allow reusing the blockchain created in CreateNewBlock_validity.
void PerformanceTest_PackageSelection(const CChainParams &chainparams,
    CScript scriptPubKey,
    std::vector<CTransactionRef> &txFirst)
{
    maxGeneratedBlock = 10000000;
    excessiveBlockSize = maxGeneratedBlock;
    dMinLimiterTxFee.Set(1.0);
    dMaxLimiterTxFee.Set(1.0);

    // Create many chains of transactions with varying fees such that we have many distinct packages within
    // each chain which could be mined as a Child Pays for Parent.
    TestMemPoolEntryHelper entry;
    SetArg("-blockprioritysize", std::to_string(0));
    CMutableTransaction tx;
    uint256 hash;
    FastRandomContext insecure_rand;

    // This script will make for a 250 byte transaction.
    CScript txnScript =
        CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP
                  << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_NOP << OP_CHECKSIG
                  << OP_1;

    int64_t nStart = GetTimeMicros();
    for (size_t j = 0; j < 10; j++)
    {
        // Make a 250 byte txn
        tx.vin.resize(1);
        tx.vin[0].scriptSig = txnScript;
        tx.vin[0].prevout.hash = txFirst[j]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout.resize(1);
        tx.vout[0].nValue = 5000000000LL;

        // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
        // of descendant packages.
        for (unsigned int i = 0; i <= 2000; ++i)
        {
            int nFee = ((insecure_rand.rand32() % 10) * 10000);
            tx.vout[0].nValue -= nFee;
            hash = tx.GetHash();
            bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
            // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
            mempool.addUnchecked(
                hash, entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }
    }
    printf("Time to load txns for %ld chains: %5.2f (secs)\n", txFirst.size(),
        (double)(GetTimeMicros() - nStart) / 1000000);
    GenerateBlocks(chainparams, scriptPubKey, 5000, 1000000, 5000);

    // Do the general run where we mine long chains where the fees are all the same. This is the most optimistic test.
    nStart = GetTimeMicros();
    for (size_t j = 0; j < 10; j++)
    {
        // Make a 250 byte txn
        tx.vin.resize(1);
        tx.vin[0].scriptSig = txnScript;
        tx.vin[0].prevout.hash = txFirst[j]->GetHash();
        tx.vin[0].prevout.n = 0;
        tx.vout.resize(1);
        tx.vout[0].nValue = 5000000000LL;

        // Create a chain of transactions with varying fees applied to the descendants. This will create a chain
        // of descendant packages.
        for (unsigned int i = 0; i <= 2000; ++i)
        {
            int nFee = 1000;
            tx.vout[0].nValue -= nFee;
            hash = tx.GetHash();
            bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
            // If we don't set the # of sig ops in the CTxMemPoolEntry, template creation fails
            mempool.addUnchecked(
                hash, entry.Fee(nFee).Time(GetTime() + i).SpendsCoinbase(spendsCoinbase).SigOps(1).FromTx(tx));
            tx.vin[0].prevout.hash = hash;
        }
    }
    printf("Time to load txns for second test: %5.2f (secs)\n", (double)(GetTimeMicros() - nStart) / 1000000);
    GenerateBlocks(chainparams, scriptPubKey, 5000, 1000000, 5000);
}

// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity)
{
    // Note was MAIN, but takes too long to generate mainnet block for a test.  Need to pre-generate them.
    // Reducing MAIN powLimit breaks ASERT pow tests
    const CChainParams &chainparams = Params(CBaseChainParams::NEXTCHAIN);
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        chainActive.reset();
        InitBlockIndex(chainparams);
    }
    assert(chainActive.Tip()->GetBlockHash() == chainparams.GetConsensus().hashGenesisBlock);
    CScript scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f"
                                                 "6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                                     << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    CMutableTransaction tx, tx2;
    CScript script;
    uint256 hash;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11;
    entry.dPriority = 111.0;
    entry.nHeight = 11;
    maxGeneratedBlock = 100000;
    excessiveBlockSize = maxGeneratedBlock;
    LOCK(cs_main);
    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Simple block creation, with coinbase message
    settingsToUserAgentString();
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Simple block creation, with coinbase message and miner message.
    settingsToUserAgentString();
    minerComment = "I am a meat popsicle.";
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    minerComment = "flying is throwing yourself against the ground and missing.  This comment is "
                   "WAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY too long.";
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;

    // We can't make transactions until we have inputs
    // Generate 110 blocks, trying pregenerated data first
    bool hadToGenerate = false;
    for (unsigned int i = 0; i < 110; ++i)
    {
        CBlock *pblock = &pblocktemplate->block; // pointer for convenience
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 1;
        txCoinbase.vin[0].scriptSig = CScript() << i;
        txCoinbase.vin[0].scriptSig.push_back(tip->height() + 1);
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        if (txFirst.size() == 0)
            baseheight = chainActive.Height();
        if (txFirst.size() < 10)
            txFirst.push_back(pblock->vtx[0]);

        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock, chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->nonce.resize(0);
        auto sz1 = pblock->CalculateBlockSize();
        pblock->nonce.resize(16);
        auto sz2 = pblock->CalculateBlockSize();
        pblock->nonce.resize(1);
        auto sz3 = pblock->CalculateBlockSize();
        BOOST_CHECK(sz1 == sz2);
        BOOST_CHECK(sz2 == sz3);

        if (i < sizeof(blockinfo) / sizeof(*blockinfo))
        {
            pblock->nonce = ParseHex(blockinfo[i].nonceHex); // start with the nonce that works
        }
        else
        {
            pblock->nonce.resize(5);
            for (int j = 0; j < 5; j++)
                pblock->nonce[i] = 0;
        }
        pblock->UpdateHeader();
        // Try the provided nonce first
        bool found = MineBlock(*pblock, 1UL, chainparams.GetConsensus());
        if (!found)
        {
            hadToGenerate = true;
            printf("Supplied nonce failed on index %d.  Generating a block with work %x\n", i, pblock->nBits);
            found = ThreadedMineBlock(12, *pblock, 1000000000UL, chainparams.GetConsensus());
            printf("Solution: { \"%s\" }\n", HexStr(pblock->nonce).c_str());
        }
        assert(found);
        // If this is extremely slow, you need to re-generate (changed mining alg or block format)
        // by taking these nonce printouts and copying them above
        CValidationState state;
        bool presult = ProcessNewBlock(state, chainparams, nullptr, pblock, true, nullptr, false);
        if (!presult)
        {
            printf("failed\n");
        }
        BOOST_CHECK(presult);
        BOOST_CHECK_MESSAGE(state.IsValid(), state.GetRejectReason() + " " + state.GetDebugMessage());
    }
    if (hadToGenerate)
    {
        printf("to speed this up paste this data in miner_tests.cpp blockinfo:\n");
        auto idx = chainActive.Tip();
        std::string dumpNonces;
        for (int i = 0; i < 110 && idx != nullptr && idx->pprev != nullptr; i++, idx = idx->pprev)
        {
            dumpNonces.insert(0, strprintf("{ \"%s\" },\n", HexStr(idx->nonce())));
        }
        printf("%s", dumpNonces.c_str());
        printf("chain generation/recovery finished\n");
    }

    // Just to make sure we can still make simple blocks
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    mempool.clear();
    tx.vin.resize(1);
    // NOTE: OP_NOP is used to force 20 SigOps for the CHECKMULTISIG
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_0 << OP_0 << OP_NOP << OP_CHECKMULTISIG << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);

    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy;
    for (unsigned int i = 0; i < 1001; ++i)
    {
        tx.vout[0].nValue -= 1000000 / 5;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        // If we do set the # of sig ops in the CTxMemPoolEntry, template creation passes
        mempool.addUnchecked(
            hash, entry.Fee(1000000 / 5).Time(GetTime()).SpendsCoinbase(spendsCoinbase).SigOps(20).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Now generate lots of full size blocks and verify that none exceed the maxGeneratedBlock value, the mempool has
    // 65k bytes of tx in it so this code will test both saturated and unsaturated blocks.
    for (unsigned int i = 2000; i <= 80000; i += 2000)
    {
        maxGeneratedBlock = i;

        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block.fExcessive == false);
        BOOST_CHECK(pblocktemplate->block.GetBlockSize() <= maxGeneratedBlock);
        unsigned int blockSize = ::GetSerializeSize(pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(blockSize <= maxGeneratedBlock);
        // printf("%lu %lu <= %lu\n", (long unsigned int) blockSize, (long unsigned int)
        // pblocktemplate->block.GetBlockSize(), (long unsigned int) maxGeneratedBlock);
    }

    BOOST_CHECK(chainActive.Tip()->height() == 110);
    uint64_t minRoom = 1000;

    // Test no reserve and standard length miner comment
    coinbaseReserve.Set(0);
    minerComment = "I am a meat popsicle.";

    // Now generate lots of full size blocks and verify that none exceed the maxGeneratedBlock value
    for (unsigned int i = 2000; i <= 30000; i += 67)
    {
        maxGeneratedBlock = i;

        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block.fExcessive == false);
        BOOST_CHECK(pblocktemplate->block.GetBlockSize() <= maxGeneratedBlock);
        if (pblocktemplate->block.GetBlockSize() > maxGeneratedBlock)
        {
            printf("Error\n");
        }
        unsigned int blockSize = ::GetSerializeSize(pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(blockSize <= maxGeneratedBlock);
        minRoom = std::min(minRoom, maxGeneratedBlock - blockSize);
        // printf("%lu %lu <= %lu\n", (long unsigned int) blockSize, (long unsigned int)
        // pblocktemplate->block.GetBlockSize(), (long unsigned int) maxGeneratedBlock);
    }

    // Assert we went right up to the limit.  We reserved 4 bytes for height but only use 2 as height is 110.
    // We also reserved 5 bytes for tx count but only use 3 as we don't have > 65535 txs in a block
    BOOST_CHECK(minRoom >= 0);

    minRoom = 1000;
    std::string testMinerComment("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvw"
                                 "xyzABCDEFGHIJKLM__________");
    // Now generate lots of full size blocks and verify that none exceed the maxGeneratedBlock value
    // printf("test mining with different sized miner comments");
    for (unsigned int i = 2000; i <= 40000; i += 89)
    {
        maxGeneratedBlock = i;
        if ((i % 100) > 0)
            minerComment = testMinerComment.substr(0, i % 100);
        else
            minerComment = "";
        // minerComment = testMinerComment.substr(0,i%100);
        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        BOOST_CHECK(pblocktemplate);
        BOOST_CHECK(pblocktemplate->block.fExcessive == false);
        BOOST_CHECK(pblocktemplate->block.GetBlockSize() <= maxGeneratedBlock);
        unsigned int blockSize = ::GetSerializeSize(pblocktemplate->block, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK(blockSize <= maxGeneratedBlock);
        minRoom = std::min(minRoom, maxGeneratedBlock - blockSize);
        // printf("%lu %lu (miner comment is %d) <= %lu\n", (long unsigned int) blockSize, (long unsigned int)
        // pblocktemplate->block.GetBlockSize(), i%100, (long unsigned int) maxGeneratedBlock);
    }


    BOOST_CHECK(minRoom >= 0);
    mempool.clear();

    // block size > limit
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<unsigned char> vchData(520);
    for (unsigned int i = 0; i < 18; ++i)
        tx.vin[0].scriptSig << vchData << OP_DROP;
    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vout[0].nValue = chainparams.GetConsensus().initialSubsidy;
    for (unsigned int i = 0; i < 128; ++i)
    {
        tx.vout[0].nValue -= 1000000;
        hash = tx.GetHash();
        bool spendsCoinbase = (i == 0) ? true : false; // only first tx spends coinbase
        mempool.addUnchecked(hash, entry.Fee(100000).Time(GetTime()).SpendsCoinbase(spendsCoinbase).FromTx(tx));
        tx.vin[0].prevout.hash = hash;
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // orphan in mempool, template creation fails
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(1000000).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error,
        HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // child with higher priority than parent
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    tx.vout[0].nValue = 490000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(10000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin.resize(2);
    tx.vin[1].scriptSig = CScript() << OP_1;
    tx.vin[1].prevout.hash = txFirst[0]->GetHash();
    tx.vin[1].prevout.n = 0;
    tx.vout[0].nValue = 590000000LL;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(40000000LL).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));
    mempool.clear();

    // coinbase in mempool, template creation fails
    tx.vin.resize(1);
    tx.vin[0].prevout.SetNull();
    tx.vin[0].scriptSig = CScript() << OP_0 << OP_1;
    tx.vout[0].nValue = 0;
    hash = tx.GetHash();
    // give it a fee so it'll get mined
    mempool.addUnchecked(hash, entry.Fee(100000).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-cb-multiple
    BOOST_CHECK_EXCEPTION(
        BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-cb-multiple"));
    mempool.clear();

    CAmount feeAmt = chainparams.GetConsensus().initialSubsidy / 1000LL;
    CAmount outAmt = chainparams.GetConsensus().initialSubsidy - feeAmt;
    // invalid (pre-p2sh) txn in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = outAmt;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(script));
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout.hash = hash;
    tx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(script.begin(), script.end());
    tx.vout[0].nValue -= feeAmt;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));

    xvalTweak.Set(false);
    BOOST_CHECK_EXCEPTION(
        BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error, HasReason("bad-blk-signatures"));
    mempool.clear();
    xvalTweak.Set(true);

    // double spend txn pair in mempool, template creation fails
    tx.vin[0].prevout.hash = txFirst[0]->GetHash();
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = outAmt;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(feeAmt).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(BlockAssembler(chainparams).CreateNewBlock(scriptPubKey), std::runtime_error,
        HasReason("bad-txns-inputs-missingorspent"));
    mempool.clear();

    // subsidy changing
    int nHeight = chainActive.Height();
    // Create an actual 209999-long block chain (without valid blocks).
    uint32_t chainTgtBits = UintToArith256(chainparams.GetConsensus().powLimit).GetCompact();
    while (chainActive.Tip()->height() < 209999)
    {
        CBlockIndex *prev = chainActive.Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->header.nBits = chainTgtBits;
        next->header.chainWork = ArithToUint256(prev->chainWork() + GetBlockProof(*next));
        next->header.height = prev->height() + 1;
        next->BuildSkip();
        chainActive.SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Extend to a 210000-long block chain.
    while (chainActive.Tip()->height() < 210000)
    {
        CBlockIndex *prev = chainActive.Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new uint256(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->header.height = prev->height() + 1;
        next->BuildSkip();
        chainActive.SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Delete the dummy blocks again.
    while (chainActive.Tip()->height() > nHeight)
    {
        CBlockIndex *del = chainActive.Tip();
        chainActive.SetTip(del->pprev);
        pcoinsTip->SetBestBlock(del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(chainActive.Tip()->GetMedianTimePast() + 1);
    int flags = LOCKTIME_VERIFY_SEQUENCE | LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // relative height locked
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    tx.vin[0].prevout.hash = txFirst[0]->GetHash(); // only 1 transaction
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].nSequence = chainActive.Tip()->height() + 1; // txFirst[0] is the 2nd block
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = 4900000000LL;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Fee(100000000L).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(MakeTransactionRef(tx), flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    // Sequence locks pass on 2nd block
    BOOST_CHECK(
        SequenceLocks(MakeTransactionRef(tx), flags, &prevheights, CreateBlockIndex(chainActive.Tip()->height() + 2)));

    // relative time locked
    tx.vin[0].prevout.hash = txFirst[1]->GetHash();
    // txFirst[1] is the 3rd block
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
                          (((chainActive.Tip()->GetMedianTimePast() + 1 - chainActive[1]->GetMedianTimePast()) >>
                               CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
                              1);
    prevheights[0] = baseheight + 2;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(CheckFinalTx(MakeTransactionRef(tx), flags)); // Locktime passes
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        // Trick the MedianTimePast
        chainActive.Tip()->GetAncestor(chainActive.Tip()->height() - i)->header.nTime += 512;
    // Sequence locks pass 512 seconds later
    BOOST_CHECK(
        SequenceLocks(MakeTransactionRef(tx), flags, &prevheights, CreateBlockIndex(chainActive.Tip()->height() + 1)));
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        chainActive.Tip()->GetAncestor(chainActive.Tip()->height() - i)->header.nTime -= 512; // undo tricked MTP

    // absolute height locked
    tx.vin[0].prevout.hash = txFirst[2]->GetHash();
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = chainActive.Tip()->height() + 1;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(MakeTransactionRef(tx), flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    // Locktime passes on 2nd block
    BOOST_CHECK(
        IsFinalTx(MakeTransactionRef(tx), chainActive.Tip()->height() + 2, chainActive.Tip()->GetMedianTimePast()));

    // absolute time locked
    tx.vin[0].prevout.hash = txFirst[3]->GetHash();
    tx.nLockTime = chainActive.Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    hash = tx.GetHash();
    mempool.addUnchecked(hash, entry.Time(GetTime()).FromTx(tx));
    BOOST_CHECK(!CheckFinalTx(MakeTransactionRef(tx), flags)); // Locktime fails
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    // Locktime passes 1 second later
    BOOST_CHECK(
        IsFinalTx(MakeTransactionRef(tx), chainActive.Tip()->height() + 2, chainActive.Tip()->GetMedianTimePast() + 1));

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout.hash = hash;
    prevheights[0] = chainActive.Tip()->height() + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;
    BOOST_CHECK(CheckFinalTx(MakeTransactionRef(tx), flags)); // Locktime passes
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    BOOST_CHECK(TestSequenceLocks(tx, flags)); // Sequence locks pass
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    BOOST_CHECK(!TestSequenceLocks(tx, flags)); // Sequence locks fail

#if 0 // TODO: removed because BIP68 is enabled on block 0
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // None of the of the absolute height/time locked tx should have made
    // it into the template because we still check IsFinalTx in CreateNewBlock,
    // but relative locked txs will if inconsistently added to mempool.
    // For now these will still generate a valid template until BIP68 soft fork
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3);
    // However if we advance height by 1 and time by 512, all of them should be mined
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++)
        // Trick the MedianTimePast
        chainActive.Tip()->GetAncestor(chainActive.Tip()->height() - i)->header.nTime += 512;
    chainActive.Tip()->header.height++;
    SetMockTime(chainActive.Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5);

    chainActive.Tip()->header.height--;
    SetMockTime(0);
#endif
    mempool.clear();

    // Test package selection
    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    // Do a performance test of package selection. This will typically be commented out unless one wants
    // to run the testing.
    mempool.clear();
    // PerformanceTest_PackageSelection(chainparams, scriptPubKey, txFirst);

    fCheckpointsEnabled = true;
}

BOOST_AUTO_TEST_SUITE_END()
