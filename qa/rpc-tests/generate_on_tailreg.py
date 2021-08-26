#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class BlockTest(BitcoinTestFramework):

    def __init__(self, test_assertion='success'):
        self.rep = False
        BitcoinTestFramework.__init__(self)

    def setup_chain(self):
        print ("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 3)

    def setup_network(self, split=False):
        node_opts = [
            "-regtest=0",
            "-tailreg=1",
            "-debug=all",
        ]

        self.nodes = [
            start_node(0, self.options.tmpdir, node_opts),
        ]

        interconnect_nodes(self.nodes)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        self.nodes[0].generate(1)
        self.sync_all()

if __name__ == '__main__':
    BlockTest().main()
