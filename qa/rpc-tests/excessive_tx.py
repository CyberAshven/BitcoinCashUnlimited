#!/usr/bin/env python3
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Test emergent consensus scenarios

import time
import random
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.util import *
from test_framework.blocktools import *
import test_framework.script as script
import pdb
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging


def mostly_sync_mempools(rpc_connections, difference=50, wait=1, verbose=1):
    """
    Wait until everybody has the most of the same transactions in their memory
    pools. There is no guarantee that mempools will ever sync due to the
    filterInventoryKnown bloom filter.
    """
    iterations = 0
    while True:
        iterations += 1
        pool = set(rpc_connections[0].getrawmempool())
        num_match = 1
        poolLen = [len(pool)]
        for i in range(1, len(rpc_connections)):
            tmp = set(rpc_connections[i].getrawmempool())
            if tmp == pool:
                num_match = num_match + 1
            if iterations > 10 and len(tmp.symmetric_difference(pool)) < difference:
                num_match = num_match + 1
            poolLen.append(len(tmp))
        if verbose:
            logging.info("sync mempool: " + str(poolLen))
        if num_match == len(rpc_connections):
            break
        time.sleep(wait)


class ExcessiveBlockTest (BitcoinTestFramework):
    def __init__(self, extended=False):
        self.extended = extended
        BitcoinTestFramework.__init__(self)

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net", "-debug=graphene", "-usecashaddr=0", "-rpcservertimeout=0"], timewait=60 * 10))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=net", "-debug=graphene", "-usecashaddr=0", "-rpcservertimeout=0"], timewait=60 * 10))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-debug=net", "-debug=graphene", "-usecashaddr=0", "-rpcservertimeout=0"], timewait=60 * 10))
        self.nodes.append(start_node(3, self.options.tmpdir, ["-debug=net", "-debug=graphene", "-usecashaddr=0", "-rpcservertimeout=0"], timewait=60 * 10))

        interconnect_nodes(self.nodes)
        self.is_network_split = False
        self.sync_all()

        if 0:  # getnewaddress can be painfully slow.  This bit of code can be used to during development to
               # create a wallet with lots of addresses, which then can be used in subsequent runs of the test.
               # It is left here for developers to manually enable.
            TEST_SIZE = 100  # TMP 00
            print("Creating addresses...")
            self.nodes[0].keypoolrefill(TEST_SIZE + 1)
            addrs = [self.nodes[0].getnewaddress() for _ in range(TEST_SIZE + 1)]
            with open("walletAddrs.json", "w") as f:
                f.write(str(addrs))
                pdb.set_trace()

    def run_test(self):
        BitcoinTestFramework.run_test(self)
        self.testCli()

        # clear out the mempool
        for n in self.nodes:
            while len(n.getrawmempool()):
                n.generate(1)
                sync_blocks(self.nodes)
        logging.info("cleared mempool: %s" % str([len(x) for x in [y.getrawmempool() for y in self.nodes]]))
        self.testExcessiveTx()

    def testCli(self):
        try:
            self.nodes[0].setminingmaxblock(1001)
        except JSONRPCException as e:
            pass
        else:
            assert(0)  # was able to set the mining size > the excessive size

        try:
            self.nodes[0].setminingmaxblock(99)
        except JSONRPCException as e:
            pass
        else:
            assert(0)  # was able to set the mining size below our arbitrary minimum

        self.nodes[0].setminingmaxblock(800)
        try:
            self.nodes[0].setexcessiveblock(799)
        except JSONRPCException as e:
            pass
        else:
            assert(0)  # was able to set the excessive size < the mining size

    def sync_all(self):
        """Synchronizes blocks and mempools (mempools may never fully sync)"""
        if self.is_network_split:
            sync_blocks(self.nodes[:2])
            sync_blocks(self.nodes[2:])
            mostly_sync_mempools(self.nodes[:2])
            mostly_sync_mempools(self.nodes[2:])
        else:
            sync_blocks(self.nodes)
            mostly_sync_mempools(self.nodes)

    def expectHeights(self, blockHeights, waittime=10):
        loop = 0
        count = []
        while loop < waittime:
            counts = [x.getblockcount() for x in self.nodes]
            if counts == blockHeights:
                return True  # success!
            else:
                for (a,b) in zip(counts, blockHeights):
                    if counts > blockHeights:
                        assert("blockchain synced too far")
            time.sleep(.25)
            loop += .25
            if int(loop) == loop and (int(loop) % 10) == 0:
                logging.info("...waiting %f %s != %s" % (loop, counts, blockHeights))
        return False

    def generateTx(self, node, txBytes, addrs, data=None):
        wallet = node.listunspent()
        wallet.sort(key=lambda x: x["amount"], reverse=False)
        logging.info("Wallet length is %d" % len(wallet))

        size = 0
        count = 0
        decContext = decimal.getcontext().prec
        decimal.getcontext().prec = 8 + 8  # 8 digits to get to 21million, and each bitcoin is 100 million satoshis
        while size < txBytes:
            count += 1
            utxo = wallet.pop()
            outp = {}
            # Make the tx bigger by adding addtl outputs so it validates faster
            payamt = satoshi_round(utxo["amount"] / decimal.Decimal(8.0))
            for x in range(0, 8):
                # its test code, I don't care if rounding error is folded into the fee
                outp[addrs[(count + x) % len(addrs)]] = payamt
                #outscript = self.wastefulOutput(addrs[(count+x)%len(addrs)])
                #outscripthex = hexlify(outscript).decode("ascii")
                #outp[outscripthex] = payamt
            if data:
                outp["data"] = data
            txn = createrawtransaction([utxo], outp, createWastefulOutput)
            # txn2 = node.createrawtransaction([utxo], outp)
            signedtxn = node.signrawtransaction(txn)
            size += len(binascii.unhexlify(signedtxn["hex"]))
            node.sendrawtransaction(signedtxn["hex"])
        logging.info("%d tx %d length" % (count, size))
        decimal.getcontext().prec = decContext
        return (count, size)


    def testExcessiveTx(self):
        """
           The test validates the rejection of a > 100kb transaction in a > 1MB block.
        """
        TEST_SIZE = 20
        logging.info("Test excessive transactions")
        if 1:
            tips = self.nodes[0].getchaintips()

            self.nodes[0].setexcessiveblock(2000000)
            self.nodes[1].setexcessiveblock(2000000)
            self.nodes[2].setexcessiveblock(2000000)
            self.nodes[3].setexcessiveblock(2000000)

            self.sync_all()
            # verify mempool is cleaned up on all nodes
            mbefore = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
            assert_equal(mbefore, [(0, 0)] * 4)

            if 1:
                logging.info("Creating addresses...")
                self.nodes[0].keypoolrefill(TEST_SIZE + 1)
                addrs = [self.nodes[0].getnewaddress() for _ in range(TEST_SIZE + 1)]
            else:  # enable if you are using a pre-created wallet, as described above
                logging.info("Loading addresses...")
                with open("wallet10kAddrs.json") as f:
                    addrs = json.load(f)

            if 1:  # Test not relaying a large transaction

                # Make the excessive transaction size smaller so its quicker to produce a excessive one
                self.nodes[0].set("net.excessiveTx=10000")
                self.nodes[1].set("net.excessiveTx=10000")
                self.nodes[2].set("net.excessiveTx=10000")
                self.nodes[3].set("net.excessiveTx=10000")
                self.nodes[0].setminingmaxblock(1000000)
                self.nodes[1].setminingmaxblock(1000000)
                self.nodes[2].setminingmaxblock(1000000)
                self.nodes[3].setminingmaxblock(1000000)

                wallet = self.nodes[0].listunspent()
                wallet.sort(key=lambda x: x["amount"], reverse=True)
                while len(wallet) < 500:
                    # Create a LOT of UTXOs
                    logging.info("Create lots of UTXOs...")
                    n = 0
                    group = min(100, TEST_SIZE)
                    count = 0
                    for w in wallet:
                        count += 1
                        split_transaction(self.nodes[0], [w], addrs[n:group + n])
                        n += group
                        if n >= len(addrs):
                            n = 0
                        if count > 50:  # We don't need any more
                            break
                    logging.info("mine blocks")
                    self.nodes[0].generate(5)  # mine all the created transactions
                    logging.info("sync all blocks and mempools")
                    self.sync_blocks()

                    wallet = self.nodes[0].listunspent()
                    wallet.sort(key=lambda x: x["amount"], reverse=True)

                logging.info("clean out the mempool")
                mbefore = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
                while mbefore != [(0, 0)] * 4:
                    time.sleep(1)
                    self.nodes[0].generate(1)
                    time.sleep(10)
                    mbefore = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]

                # we need the mempool to be empty to track that this one tx doesn't prop
                assert_equal(mbefore, [(0, 0)] * 4)

                logging.info("Test not relaying a large transaction")

                (tx, vin, vout, txid) = split_transaction(self.nodes[0], wallet[0:500], [addrs[0]], txfeePer=60)
                logging.debug("Transaction Length is: ", len(binascii.unhexlify(tx)))
                assert(len(binascii.unhexlify(tx)) > 10000)  # txn has to be big for the test to work

                mbefore = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
                assert_equal(mbefore[1:], [(0, 0), (0, 0), (0, 0)])  # verify that the transaction did not propagate
                assert(mbefore[0][0] > 0)  # verify that the transaction is in my node

                logging.info("allowing tx a chance to propagate - sleeping...")
                while len(self.nodes[0].getmempoolinfo()) < 1:
                    logging.info("sleeping 1")
                    time.sleep(1)

                logging.info("Test a large transaction in block < 1MB")
                try:
                    largeBlock = self.nodes[0].generate(1)
                except JSONRPCException as e:
                    assert_equal(e.error["message"], "CreateNewBlock: TestBlockValidity failed: bad-tx-size (code 16)")
                else:
                    assert(0)  # was able to mine a block with an excessive tx

            # this test checks the behavior of > 1MB blocks with excessive
            # transactions.  it takes a LONG time to generate and propagate 1MB+ txs.
            if self.extended:

                logging.info("Creating addresses...")
                self.nodes[0].keypoolrefill(2000)
                addrs = [self.nodes[0].getnewaddress() for _ in range(2000)]
                # Create a LOT of UTXOs for the next test
                wallet = self.nodes[0].listunspent()
                wallet.sort(key=lambda x: x["amount"], reverse=True)
                wlen = len(wallet)
                while wlen < 8000:
                    logging.info("Create lots of UTXOs by 100...")
                    n = 0
                    for w in wallet:
                        split_transaction(self.nodes[0], [w], addrs[n:100 + n])
                        logging.info(str(wlen))
                        n += 100
                        if n >= len(addrs):
                            n = 0
                        wlen += 99
                        if wlen > 8000:
                            break

                    blk = self.nodes[0].generate(1)
                    blkinfo = self.nodes[0].getblock(blk[0])
                    logging.info("Generated block %d size: %d, num tx: %d" %
                                 (blkinfo["height"], blkinfo["size"], len(blkinfo["tx"])))
                    wallet = self.nodes[0].listunspent()
                    wallet.sort(key=lambda x: x["amount"], reverse=True)
                    wlen = len(wallet)

                self.nodes[0].generate(1)
                self.sync_blocks()

                logging.info("Building > 1MB block...")
                # Set the excessive transaction size larger for this node so we can
                # generate an "excessive" block for the other nodes
                self.nodes[0].set("net.excessiveTx=1000000")

                self.generateTx(self.nodes[0], 1000000, addrs)

                # Now generate a > 100kb transaction & mine it into a > 1MB block

                self.nodes[0].setminingmaxblock(2000000)
                self.nodes[0].setexcessiveblock(2000000)

                wallet.sort(key=lambda x: x["amount"], reverse=True)
                (tx, vin, vout, txid) = split_transaction(self.nodes[0], wallet[0:2500], [addrs[0]], txfeePer=60)
                logging.debug("Transaction Length is: ", len(binascii.unhexlify(tx)))
                assert(len(binascii.unhexlify(tx)) > 100000)  # txn has to be big for the test to work

                origCounts = [x.getblockcount() for x in self.nodes]
                base = origCounts[0]
                mpool = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
                logging.debug(str(mpool))
                largeBlock = self.nodes[0].generate(1)
                mpool = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
                logging.debug(str(mpool))

                logging.info("Syncing node1")
                largeBlock2 = self.nodes[0].generate(1)
                sync_blocks(self.nodes[0:2])
                mpool = [(lambda y: (y["size"], y["bytes"]))(x.getmempoolinfo()) for x in self.nodes]
                logging.debug(str(mpool))
                self.expectHeights([base + 2, base + 2, base, base], 30)

                logging.info("Syncing node2")
                largeBlock3 = self.nodes[0].generate(1)
                sync_blocks(self.nodes[0:3])
                self.expectHeights([base + 3, base + 3, base + 3, base], 30)

                logging.info("Syncing node3")
                largeBlock4 = self.nodes[0].generate(1)
                sync_blocks(self.nodes)
                self.expectHeights([base + 4, base + 4, base + 4, base + 4], 30)

            # Put it back to the default
            self.nodes[0].set("net.excessiveTx=1000000")
            self.nodes[1].set("net.excessiveTx=1000000")
            self.nodes[2].set("net.excessiveTx=1000000")
            self.nodes[3].set("net.excessiveTx=1000000")

if __name__ == '__main__':

    if "--extensive" in sys.argv:
        longTest = True
        # we must remove duplicate 'extensive' arg here
        while True:
            try:
                sys.argv.remove('--extensive')
            except:
                break
        logging.info("Running extensive tests")
    else:
        longTest = False

    ExcessiveBlockTest(longTest).main()


def info(type, value, tb):
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import traceback
        import pdb
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        print
        # ...then start the debugger in post-mortem mode.
        pdb.pm()


sys.excepthook = info

def Test():
    t = ExcessiveBlockTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000,  # we don't want any transactions rejected due to insufficient fees...
        "blockminsize": 1000000
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
