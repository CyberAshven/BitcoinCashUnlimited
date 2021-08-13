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
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self, split=False):
        node_opts = [
            "-regtest=0",
            "-tailreg=1",
            "-rpcservertimeout=0",
            "-debug=all",
            "-use-grapheneblocks=0",
            "-excessiveblocksize=6000000",
            "-blockprioritysize=6000000",
            "-blockmaxsize=6000000"]

        self.nodes = [
            start_node(0, self.options.tmpdir, node_opts),
            start_node(1, self.options.tmpdir, node_opts)
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
        # Generate some blocks
        self.nodes[0].generatetailstormblocks(105)
        self.sync_blocks()

        self.testGetBlock()

        logging.info("Send 5 transactions from node0 (to its own address)")
        addr = self.nodes[0].getnewaddress()
        for i in range(5):
            self.nodes[0].sendtoaddress(addr, Decimal("10"))

        miner_node = 0
        other_node = 1
        for i in range(30):
            new_block = self.nodes[miner_node].generatetailstormblocks(1)
            self.sync_blocks()
            assert_equal(new_block[miner_node], self.nodes[miner_node].gettailstorminfo()['chaintip'])

            # compare miner node and another node to check for proper relay
            assert_equal(self.nodes[-1].gettailstorminfo()['chaintip'], self.nodes[other_node].gettailstorminfo()['chaintip'])

        new_block = self.nodes[miner_node].generatetailstormblocks(10)
        self.sync_blocks()
        assert_equal(new_block[-1], self.nodes[miner_node].gettailstorminfo()['chaintip'])
        # compare miner node and another node to check for proper relay
        assert_equal(self.nodes[miner_node].gettailstorminfo()['chaintip'], self.nodes[other_node].gettailstorminfo()['chaintip'])

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
    }

    flags = standardFlags()
    t.main(flags, bitcoinConf, None)
