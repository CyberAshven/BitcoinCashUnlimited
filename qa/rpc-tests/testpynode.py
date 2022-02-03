#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import *

class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # pick this one to start at 0 mined blocks
        # initialize_chain_clean(self.options.tmpdir, 1, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        # Nodes to start --------^
        # Note for this template I readied 4 nodes but only started 2

        # Now interconnect the nodes
        connect_nodes_full(self.nodes)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_blocks()

    def run_test (self):
        t = "0001a028ded13238530391ae209f2abccc3d5cbe720b660e16a29d256241e9e08cd664acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacffffffff00000000000000000200000000000000000032616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000000000000000032616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616100000000"
        testtx = CTransaction(t)
        assert(testtx.toHex() == t)
        assert(uint256ToRpcHex(testtx.GetIdem()) == "af4b36761b275cf17ae5f35b27121c80f72b0c9316d65af0e8c39f88a6a3cb19")
        assert(uint256ToRpcHex(testtx.GetId()) == "78b7905f328d0fdefd7388972a215ea5cb58f567a250f9bac84c26715b548451")

        blkhash = self.nodes[0].generate(1)[0]
        blkjson = self.nodes[0].getblock(blkhash)
        blkhex  = self.nodes[0].getblock(blkhash, False)
        blk = CBlock(blkhex)

        assert(blk.nTime == blkjson["time"])
        assert(ser_uint256(blk.hashMerkleRoot)[::-1].hex() == blkjson["merkleroot"])
        for i in range(len(blk.vtx)):
            t = blk.vtx[i]
            tid = t.GetId()
            tidem = t.GetIdem()
            assert (blkjson["txid"][i] == uint256ToRpcHex(tid))
            assert (blkjson["txidem"][i] == uint256ToRpcHex(tidem))

        assert(uint256ToRpcHex(blk.hashMerkleRoot) == blkjson["merkleroot"])
        assert(blk.hashMerkleRoot == blk.calc_merkle_root())

        unspent = self.nodes[0].listunspent()
        for u in unspent:
            #print(u['outpoint'])
            outpt = COutPoint()
            outpt.fromIdemAndIdx(u['txidem'],u['vout'])
            # print(uint256ToRpcHex(outpt.hash))
            assert(uint256ToRpcHex(outpt.hash) == u['outpoint'])

        # Now try block with a few tx
        for i in range(1,20):
            vtx = {}
            for j in range(0,i):
                addr = self.nodes[0].getnewaddress()
                txhash = self.nodes[0].sendtoaddress(addr,1000000)
                txjson = self.nodes[0].gettransaction(txhash)
                tx = CTransaction()
                tx.deserialize(txjson["hex"])
                assert(txjson["txidem"] == uint256ToRpcHex(tx.GetIdem()))
                assert(txjson["txid"] == uint256ToRpcHex(tx.GetId()))
                vtx[tx] = txjson

            blkhash = self.nodes[0].generate(1)[0]
            blkjson = self.nodes[0].getblock(blkhash)
            blkhex  = self.nodes[0].getblock(blkhash, False)
            blk = CBlock(blkhex)

            assert(len(blkjson["txid"]) == i+1) # +1 for coinbase
            for j in range(len(blk.vtx)):
                t = blk.vtx[j]
                tid = t.GetId()
                tidem = t.GetIdem()
                assert (blkjson["txid"][j] == uint256ToRpcHex(tid))
                assert (blkjson["txidem"][j] == uint256ToRpcHex(tidem))

            assert(uint256ToRpcHex(blk.hashMerkleRoot) == blkjson["merkleroot"])
            assert(blk.hashMerkleRoot == blk.calc_merkle_root())




if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    flags = standardFlags()
    # flags[0]='--tmpdir=/ramdisk/test/t1'
    t.main(flags, bitcoinConf, None)
