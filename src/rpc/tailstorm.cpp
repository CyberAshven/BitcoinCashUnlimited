// Copyright (c) 2020 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "blockstorage/blockstorage.h"
#include "tailstorm/tailstorm.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "dstencode.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "pow.h"
#include "rpc/server.h"
#include "txadmission.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"
#include "validation/parallel.h"

#include <cstdlib>
#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/shared_ptr.hpp>

extern CTailstormDagSet tailstormDagSet;
extern std::set<CTailstormBlock> tailstormBlocks;
UniValue SubblockToJSON(const CSubBlock &block, bool txDetails, bool listTxns);


static UniValue getsubblock(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error(
            "getsubblock hash_or_height ( verbosity ) ( tx_count )\n"
            "\nUse blockHeight:subblockIndex to specify a subblock by height\n"
            "If verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbosity is 1, returns the block header with a list of transaction hashes in the block\n"
            "If verbosity is 2, returns the block header with a list of all decoded transaction details in the block\n"
            "If tx_count is true, returns a block header with a count of all transactions in the block.\n"
            "\nArguments:\n"
            "1. \"hash_or_height\"      (string|numeric, required) The block hash or height.\n"
            "2. \"verbosity\"           (numeric, optional, default=1) 0 for hex-encoded data, 1 \n"
            "                          for a block header with list of txn hashes, and 2 for a block header with \n"
            "                          detailed transaction data.\n"
            "3. \"tx_count\"            (boolean, optional, default=false true to get a block header with a count of \n"
            "                          of transactions in the block.\n"
            "\nResult (for verbosity = 1, tx_count = false):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main "
            "chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"versionHex\" : \"00000000\", (string) The block version formatted in hexadecimal\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"chainwork\" : \"xxxx\",  (string) Expected number of hashes required to produce the chain up to this "
            "block (in hex)\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "}\n"
            "\nResult (for verbosity = 2, tx_count = false):\n"
            "{\n"
            "Same as for verbosity = 1 but with all the un-encoded details of each transaction\n"
            "}\n"
            "\nResult (for verbosity=0):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"
            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"") +
            HelpExampleRpc("getblock", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\""));

    const std::string param0 = params[0].get_str();
    CSubBlock subblock;
    bool found = false;
    if (param0.find(':') == std::string::npos)  // not found, so must be a hash
    {
        // Grab the subblock by hash
        const uint256 hash(uint256S(param0));

        // Look to see if its an active subblock
        {
            LOCK(cs_tipDagCache);
            found = tailstormDagSet.Find(hash, subblock);
        }

        if (!found)  // Look for a dag subblock
        {
            std::map<uint256, CDagNode>::iterator iter;
            LOCK(cs_tipDagCache);
            iter = tipDagCache.find(hash);
            if (iter != tipDagCache.end())
            {
                subblock = iter->second.subblock;
                found = true;
            }
        }

        if (!found)  // Look for a committed subblock
        {
            found = FindCommittedSubblock(chainActive, hash, subblock);
        }
    }
    else
    {
        // TODO find the height and index
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unimplemented");
    }

    if (!found) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown subblock");

    int nVerbose = 1;
    bool fListTxns = true;
    if (params.size() > 1)
    {
        if (params[1].isNum())
            nVerbose = params[1].get_int();
        else
            nVerbose = IsStringTrue(params[1].get_str());
    }
    if (params.size() == 3)
    {
        fListTxns = !(IsStringTrue(params[2].get_str()));
    }

    bool fVerbose = false;
    if (nVerbose == 1)
        fVerbose = false;
    else if (nVerbose == 2)
        fVerbose = true;

    if (nVerbose == 0 && fListTxns == true)
    {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << subblock;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return SubblockToJSON(subblock, fVerbose, fListTxns);
}


UniValue SubblockToJSON(const CSubBlock &block, bool txDetails, bool listTxns)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", block.GetHash().GetHex());
    result.pushKV("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION));
    result.pushKV("version", block.nVersion);
    result.pushKV("versionHex", strprintf("%08x", block.nVersion));
    result.pushKV("time", block.GetBlockTime());
    result.pushKV("bits", strprintf("%08x", block.nBits));
    result.pushKV("difficulty", GetDifficulty(block.nBits));
    result.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
    result.pushKV("merkleroothash", block.hashMerkleRoot.GetHex());

    UniValue txs(UniValue::VARR);
    if (listTxns)
    {
        int64_t txTime = -1; // Don't display the time in the tx because its in the block data.
        for (const auto &tx : block.vtx)
        {
            if (txDetails)
            {
                UniValue objTx(UniValue::VOBJ);
                TxToJSON(*tx, txTime, uint256(), objTx);
                txs.push_back(objTx);
            }
            else
            {
                txs.push_back(tx->GetHash().GetHex());
            }
        }
        result.pushKV("tx", txs);
    }
    else
    {
        result.pushKV("txcount", (uint64_t)block.vtx.size());
    }

    return result;
}



UniValue TailstormBlockToJSON(CTailstormBlockRef block, const CBlockIndex *blockindex, bool txDetails, bool listTxns)
{
    DbgAssert(blockindex, throw JSONRPCError(RPC_INVALID_REQUEST, "Called tailstorm API with index nullptr"));
    DbgAssert(blockindex->isTailstorm, throw JSONRPCError(RPC_INVALID_REQUEST, "Called tailstorm API with normal block"));

    UniValue result(UniValue::VOBJ);
    result.pushKV("hash", blockindex->GetBlockHash().GetHex());
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.pushKV("confirmations", confirmations);
    result.pushKV("size", (int)::GetSerializeSize(*block, SER_NETWORK, PROTOCOL_VERSION));
    result.pushKV("height", blockindex->nHeight);
    result.pushKV("version", block->nVersion);
    result.pushKV("versionHex", strprintf("%08x", block->nVersion));
    result.pushKV("time", block->GetBlockTime());
    result.pushKV("mediantime", (int64_t)blockindex->GetMedianTimePast());
    result.pushKV("bits", strprintf("%08x", block->nBits));
    result.pushKV("difficulty", GetDifficulty(blockindex));
    result.pushKV("chainwork", blockindex->nChainWork.GetHex());
    if (blockindex->pprev)
        result.pushKV("previousblockhash", blockindex->pprev->GetBlockHash().GetHex());
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.pushKV("nextblockhash", pnext->GetBlockHash().GetHex());

    std::set<uint256> subblockHashes;
    block->GetSubblockHashes(subblockHashes);

    UniValue sbhashes(UniValue::VARR);
    for (const auto& b : subblockHashes)
    {
        sbhashes.push_back(b.GetHex());
    }
    result.pushKV("subblockHashes", sbhashes);

    UniValue txs(UniValue::VARR);
    if (listTxns)
    {
        int64_t txTime = -1; // Don't display the time in the tx because its in the block data.
        for (const auto &tx : block->vtx)
        {
            if (txDetails)
            {
                UniValue objTx(UniValue::VOBJ);
                TxToJSON(*tx, txTime, uint256(), objTx);
                txs.push_back(objTx);
            }
            else
            {
                txs.push_back(tx->GetHash().GetHex());
            }
        }
        result.pushKV("tx", txs);
    }
    else
    {
        result.pushKV("txcount", (uint64_t)block->vtx.size());
    }
    return result;
}

UniValue TailstormBlockToJSON(const CBlockIndex *blockindex, bool txDetails, bool listTxns)
{
    DbgAssert(blockindex, throw JSONRPCError(RPC_INVALID_REQUEST, "Called tailstorm API with index nullptr"));
    DbgAssert(blockindex->isTailstorm, throw JSONRPCError(RPC_INVALID_REQUEST, "Called tailstorm API with normal block"));

    CTailstormBlockRef block(new CTailstormBlock);
    if (!ReadBlockFromDisk(block, blockindex, Params().GetConsensus()))
    {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Cannot access tailstorm block");
    }

    return TailstormBlockToJSON(block, blockindex, txDetails, listTxns);
}


UniValue generateTailstormBlocks(boost::shared_ptr<CReserveScript> coinbaseScript,
    int nSubGenerate=0,
    int nBobGenerate=0,
    uint64_t nMaxTries=0,
    bool keepScript=false,
    bool fSubBlocksOnly=false)
{
    static const int nInnerLoopCount = 0x10000;

    UniValue blockHashes(UniValue::VARR);

    int numSubBlocks = 0;
    int numBobBlocks = 0;
    std::vector<CSubBlockRef> vdag;

    // if we arent generating any blocks, return now
    if (nSubGenerate <= 0 && nBobGenerate <= 0)
    {
        return blockHashes;
    }

    while (true)
    {
        std::unique_ptr<CSubBlockTemplate> pblocktemplate;
        {
            TxAdmissionPause lock; // flush any tx waiting to enter the mempool
            pblocktemplate = SubBlockAssembler(Params()).CreateNewSubBlock(coinbaseScript->reserveScript);
        }
        if (!pblocktemplate.get())
        {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        }

        LOG(WB, "Using delta block for RPC generate.\n");
        CSubBlock *pblock = pblocktemplate->subblock.get();
        // GAS TODO: Bigger nonce to obsolete the extra nonce
        //IncrementExtraNonce(pblock, nExtraNonce);

        // Generally look for weak PoW
        while (nMaxTries > 0 && pblock->nNonce < nInnerLoopCount &&
               !CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus()))
        {
            ++pblock->nNonce;
            --nMaxTries;
        }
        if (nMaxTries == 0)
            break;

        if (pblock->nNonce == nInnerLoopCount)
            continue;

        if (CheckProofOfWork(pblock->GetHash(), pblock->nBits, Params().GetConsensus()))
        {
            // In we are mining our own block or not running in parallel for any reason
            // we must terminate any block validation threads that are currently running,
            // Unless they have more work than our own block or are processing a chain
            // that has more work than our block.
            PV->StopAllValidationThreads(pblock->GetBlockHeader().nBits);

            if (!ProcessNewSubBlock(*pblock, nullptr))
            {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewSubBlock, subblock not accepted");
            }
            LOG(WB, "Processed new subblock: %s\n", pblocktemplate->subblock->GetHash().ToString());

            // mark script as important because it was used at least for one coinbase output if the script came from the
            // wallet
            if (keepScript)
            {
                coinbaseScript->KeepScript();
            }
            // Add subblock to the dag
            vdag.push_back(pblocktemplate->subblock);
            numSubBlocks++;
            if (nSubGenerate > 0)
            {
                blockHashes.push_back(pblock->GetHash().GetHex());
            }

            if (fSubBlocksOnly == true && numSubBlocks >= nSubGenerate)
            {
                break;
            }

            if (fSubBlocksOnly == false)
            {
                // Assemble tailstorm block
                std::unique_ptr<CTailstormBlockTemplate> pTailstormBlockTemplate;

                TxAdmissionPause lock; // flush any tx waiting to enter the mempool
                pTailstormBlockTemplate = TailstormBlockAssembler(Params()).CreateNewTailstormBlock();
                if (pTailstormBlockTemplate.get())
                {
                    CTailstormBlock *pTailstormBlock = pTailstormBlockTemplate->tailstormblock.get();

                    // Check if tailstorm block meets strong PoW
                    if (CheckTailstormPoW(*pTailstormBlock, Params().GetConsensus(), TAILSTORM_K))
                    {
                        PV->StopAllValidationThreads(pTailstormBlock->GetBlockHeader().nBits);

                        CValidationState state;
                        if (!ProcessNewTailstormBlock(state, Params(), nullptr, pTailstormBlock, true, nullptr))
                        {
                            std::string msg = strprintf("ProcessNewTailstormBlock tailstorm block not accepted with code=%d, reason=%s, message=%s", state.GetRejectCode(), state.GetRejectReason(), state.GetDebugMessage());
                            LOG(WB, msg);
                            throw JSONRPCError(RPC_INTERNAL_ERROR, msg);
                        }

                        // mark script as important because it was used at least for one coinbase output if the script came from the
                        // wallet
                        if (keepScript)
                        {
                            coinbaseScript->KeepScript();
                        }
                        numBobBlocks++;

                        if (nBobGenerate > 0)
                        {
                            blockHashes.push_back(pTailstormBlock->GetHash().GetHex());
                        }
                        if (numBobBlocks >= nBobGenerate)
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
    // we dont need to flush to disk because no blocks that can be written to disk were made
    // we dont update tip because no cblocks were mined, only csubblocks
    return blockHashes;
}

UniValue generatesubblocks(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error("generatesubblocks numSubBlocks ( maxtries )\n"
                            "\nMine up to numSubBlocks subBlocks immediately (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numSubBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 subBlocks\n" +
                            HelpExampleCli("generatesubblocks", "11"));

    int nSubGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 1)
    {
        nMaxTries = params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateTailstormBlocks(coinbaseScript, nSubGenerate, 0, nMaxTries, true, true);
}

UniValue generatetailstormblocks(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw std::runtime_error("generatetailstormblocks numTailstormBlocks ( maxtries )\n"
                            "\nMine up to numTailstormBlocks tailstormBlocks immediately (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numTailstormBlocks    (numeric, required) How many tailstormBlocks are generated immediately.\n"
                            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 tailstormBlocks\n" +
                            HelpExampleCli("generatetailstormblocks", "11"));

    int nBobGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 1)
    {
        nMaxTries = params[1].get_int();
    }

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    return generateTailstormBlocks(coinbaseScript, 0, nBobGenerate, nMaxTries, true);
}

UniValue generatesubblockstoaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error("generatesubblockstoaddress numSubBlocks address (maxtries)\n"
                            "\nMine subblocks immediately to a specified address (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numSubBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. address    (string, required) The address to send the newly generated bitcoin to.\n"
                            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 subblocks to myaddress\n" +
                            HelpExampleCli("generatesubblockstoaddress", "11 \"myaddress\""));

    int nSubGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 2)
    {
        nMaxTries = params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(destination))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateTailstormBlocks(coinbaseScript, nSubGenerate, 0, nMaxTries, false, true);
}

UniValue generatetailstormblockstoaddress(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error("generatetailstormblockstoaddress numTailstormBlocks address (maxtries)\n"
                            "\nMine tailstorm blocks immediately to a specified address (before the RPC call returns)\n"
                            "\nArguments:\n"
                            "1. numTailstormBlocks    (numeric, required) How many subBlocks are generated immediately.\n"
                            "2. address    (string, required) The address to send the newly generated bitcoin to.\n"
                            "3. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
                            "\nResult\n"
                            "[ blockhashes ]     (array) hashes of blocks generated\n"
                            "\nExamples:\n"
                            "\nGenerate 11 tailstormblocks to myaddress\n" +
                            HelpExampleCli("generatetailstormblockstoaddress", "11 \"myaddress\""));

    int nBobGenerate = params[0].get_int();
    uint64_t nMaxTries = 100000000;
    if (params.size() > 2)
    {
        nMaxTries = params[2].get_int();
    }

    CTxDestination destination = DecodeDestination(params[1].get_str());
    if (!IsValidDestination(destination))
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    boost::shared_ptr<CReserveScript> coinbaseScript(new CReserveScript());
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateTailstormBlocks(coinbaseScript, 0, nBobGenerate, nMaxTries, false);
}


UniValue getdaginfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getdaginfo\n"
            "Returns an object containing info about the current tailstorm dag.\n"
            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx,           (numeric) the number of dag nodes in the dag\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getdaginfo", "") + HelpExampleRpc("getdaginfo", ""));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("size", (int) tailstormDagSet.Size());

    return obj;
}

UniValue getdagtips(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getdaginfo\n"
            "Returns an object containing info about the current tailstorm dag.\n"
            "\nResult:\n"
            "{\n"
                "[ blockhashes ]     (array) hashes of the subblocks at the dag tips\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getdaginfo", "") + HelpExampleRpc("getdaginfo", ""));
    }

    UniValue obj(UniValue::VARR);
    std::vector<uint256> tip_hashes = tailstormDagSet.GetBestDagInfo().tip_hashes;
    for (auto &hash : tip_hashes)
    {
        obj.push_back(hash.GetHex());
    }
    return obj;
}

UniValue getbestdag(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "getbestdag\n"
            "Returns the hashes of all subblocks in the best dag.\n"
            "\nResult:\n"
            "{\n"
                "[ blockhashes ]     (array) hashes of the subblocks in the best dag\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("getbestdag", "") + HelpExampleRpc("getbestdag", ""));
    }

    UniValue obj(UniValue::VARR);
    std::set<CDagNode> bestDag;
    if (!tailstormDagSet.GetBestDag(bestDag))
    {
        // there is no dog with at least TAILSTORM_K subblocks in it yet
        return obj;
    }

    for (auto &dagNode : bestDag)
    {
        obj.push_back(dagNode.hash.GetHex());
    }
    return obj;
}


UniValue gettailstorminfo(const UniValue &params, bool fHelp)
{
    if (fHelp || params.size() != 0)
    {
        throw std::runtime_error(
            "gettailstorminfo\n"
            "Returns an object containing info about the current tailstorm blocks.\n"
            "\nResult:\n"
            "{\n"
                "chaintip: hash     (array) hash of tailstorm block at tip of current chain\n"
            "}\n"
            "\nExamples:\n" +
            HelpExampleCli("gettailstorminfo", "") + HelpExampleRpc("gettailstorminfo", ""));
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("chaintip", chainActive.Tip()->phashBlock->GetHex());
    return obj;
}

/* clang-format off */
static const CRPCCommand commands[] = {
    //  category              name                      actor (function)         okSafeMode
    //  --------------------- ------------------------  -----------------------  ----------
    {"generating", "generatesubblocks", &generatesubblocks, true},
    {"generating", "generatetailstormblocks", &generatetailstormblocks, true},
    {"generating", "generatesubblockstoaddress", &generatesubblockstoaddress, true},
    {"generating", "generatesubblockstoaddress", &generatesubblockstoaddress, true},
    {"tailstorm", "getdaginfo", &getdaginfo, true},
    {"tailstorm", "getdagtips", &getdagtips, true},
    {"tailstorm", "gettailstorminfo", &gettailstorminfo, true},
    {"tailstorm", "getsubblock", &getsubblock, true},
    {"tailstorm", "getbestdag", &getbestdag, true}
};
/* clang-format on */

void RegisterTailstormRPCCommands(CRPCTable &table)
{
    for (auto cmd : commands)
        table.appendCommand(cmd);
}
