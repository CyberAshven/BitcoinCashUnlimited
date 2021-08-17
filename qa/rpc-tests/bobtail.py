#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

NUM_TAILSTORM_SUBBLOCKS = 3

class TailstormBlocksTest(BitcoinTestFramework):
    def __init__(self):
        self.rep = False
        BitcoinTestFramework.__init__(self)

    def setup_chain(self):
        print ("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 4)

    def setup_network(self, split=False):
        self.node_opts = [
            "-regtest=0",
            "-tailreg=1",
            "-rpcservertimeout=0",
            "-debug=all,-libevent",
            "-use-grapheneblocks=0",
            "-excessiveblocksize=6000000",
            "-blockprioritysize=6000000",
            "-blockmaxsize=6000000"]

        self.nodes = [
            start_node(0, self.options.tmpdir, self.node_opts),
            start_node(1, self.options.tmpdir, self.node_opts)
        ]

        self.is_network_split = False
        interconnect_nodes(self.nodes)
        self.sync_all()

    def testGetBlock(self):
        n = self.nodes[0]
        b1a = n.getblock(1)
        b1b = n.getblock(b1a["hash"])
        assert b1a == b1b
        assert b1a["confirmations"] == n.getblockcount()
        assert b1a["height"] == 1
        assert b1a["size"] < 3000
        assert b1a["version"] == int(b1a["versionHex"],16)
        assert b1a["version"] == 0x20000000
        now = int(time.time())
        assert b1a["time"] <= now
        assert b1a["time"] >= now - 60
        assert b1a["bits"] == '207fffff'
        assert b1a["chainwork"] == '0000000000000000000000000000000000000000000000000000000000000004'
        assert b1a["previousblockhash"] == 'b280fc0bb8e6adbe370304cd14f5c1d6ea40c0e12db6e42e3ecccd0dc041ce01' # Genesis block
        assert len(b1a["subblockHashes"]) == NUM_TAILSTORM_SUBBLOCKS
        b1full = n.getblock(1, 2, False)  # get all the tx as hex
        b1tx0 = b1full["tx"][0]
        assert len(b1tx0["vout"]) == NUM_TAILSTORM_SUBBLOCKS

        sb0 = n.getsubblock(b1a["subblockHashes"][0])
        assert sb0["time"] <= now
        assert sb0["time"] >= now - 60

    def run_test(self):
        LONGER = 10
        # First test corner case where there are more subblocks than necessary
        # to assemble a block. This should succeed silently.
        self.nodes[0].generatesubblocks(103)
        self.nodes[0].generatetailstormblocks(1)

        s2h = self.nodes[1].generatesubblocks(2)
        # Are they available locally?
        waitFor(10, lambda: type(returnException(lambda: self.nodes[1].getsubblock(s2h[0]))) is type({}))
        waitFor(10, lambda: type(returnException(lambda: self.nodes[1].getsubblock(s2h[1]))) is type({}))
        # Are they available remote?
        waitFor(10, lambda: type(returnException(lambda: self.nodes[0].getsubblock(s2h[0]))) is type({}))
        waitFor(10, lambda: type(returnException(lambda: self.nodes[0].getsubblock(s2h[1]))) is type({}))
        s1h = self.nodes[0].generatesubblocks(2)
        ts1h = self.nodes[0].generatetailstormblocks(1)
        ts1 = self.nodes[0].getblock(ts1h[0])
        usedSubblocks = ts1["subblockHashes"]
        genSbs = s1h + s2h
        # Make sure we didn't create new subblocks but used what we had
        for sb in usedSubblocks:
            assert(sb in genSbs)

        # TODO: not implemented
        # Make sure we preferred our own subblocks (maximize our money)
        # for sb in s1h:
        #    assert(sb in usedSubblocks)


        # Generate some blocks
        self.nodes[0].generatetailstormblocks(105)
        self.sync_blocks()

        self.testGetBlock()

        logging.info("Send 5 transactions from node0 (to its own address)")
        addr = self.nodes[0].getnewaddress()
        for i in range(5):
            self.nodes[0].sendtoaddress(addr, Decimal("10"))

        logging.info("Generate 30 tailstorm blocks with sync")
        miner_node = 0
        other_node = 1
        for i in range(3*LONGER):
            new_block = self.nodes[miner_node].generatetailstormblocks(1)
            logging.info("Sync %d: block %s" % (i, new_block))
            self.sync_blocks()
            assert_equal(new_block[miner_node], self.nodes[miner_node].gettailstorminfo()['chaintip'])

            # compare miner node and another node to check for proper relay
            assert_equal(self.nodes[-1].gettailstorminfo()['chaintip'], self.nodes[other_node].gettailstorminfo()['chaintip'])

        new_block = self.nodes[miner_node].generatetailstormblocks(10)
        self.sync_blocks()
        assert_equal(new_block[-1], self.nodes[miner_node].gettailstorminfo()['chaintip'])
        # compare miner node and another node to check for proper relay
        assert_equal(self.nodes[miner_node].gettailstorminfo()['chaintip'], self.nodes[other_node].gettailstorminfo()['chaintip'])

        # IBD test:  make a longer chain and then sync
        logging.info("generating %d blocks" % (10*LONGER))
        self.nodes[1].generatetailstormblocks(10*LONGER)
        nblocks = self.nodes[1].getblockcount()
        node2 = start_node(2, self.options.tmpdir, self.node_opts)
        self.nodes.append(node2)
        connect_nodes(node2, 0)
        logging.info("syncing 2 nodes")
        waitFor(100, lambda: node2.getblockcount() == nblocks, 2.0)
        waitFor(100, lambda: self.nodes[0].getblockcount() == nblocks, 2.0)
        pdb.set_trace()

if __name__ == '__main__':
    TailstormBlocksTest().main()

# Create a convenient function for an interactive python debugging session
def Test():
    t = TailstormBlocksTest()
    # logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().setLevel(logging.INFO)
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["all", "-event"],
        "logtimemicros": 1
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
