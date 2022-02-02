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
import random
from decimal import *
from copy import *

DSAT =       Decimal("0.00000001")
TYPICALFEE = Decimal("0.00000185")
DUST = Decimal("0.00000630")
SubsidyHalvingInterval = 150

def D(x):
    r = Decimal(x).quantize(DSAT)
    return r
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

def MonetaryBase(height):
    curReward = COINBASE_REWARD
    total = D(0)
    while True:
        if height < SubsidyHalvingInterval:
            return(total + height*curReward)
        height -= SubsidyHalvingInterval
        total += SubsidyHalvingInterval*curReward - curReward/2  # this current block is the lower amt
        curReward/=2

def randomBut(maxval, notthis):
    tmp = random.randint(0,maxval-1)
    if tmp >= notthis:
        tmp+=1
    return tmp


class MyTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        # initialize_chain(self.options.tmpdir, bitcoinConfDict, wallets)
        # pick this one to start at 0 mined blocks
        initialize_chain_clean(self.options.tmpdir, 4, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodeslots = start_nodes(4, self.options.tmpdir)
        self.nodes = copy(self.nodeslots)
        # Nodes to start --------^
        # Note for this template I readied 4 nodes but only started 2

        # Now interconnect the nodes
        connect_nodes_full(self.nodeslots)
        # Let the framework know if the network is fully connected.
        # If not, the framework assumes this partition: (0,1) and (2,3)
        # For more complex partitions, you can't use the self.sync* member functions
        self.is_network_split=False
        self.sync_blocks()

    def anyLiveNodeIdx(self):
        return random.randint(0,len(self.nodes)-1)
    def anyNodeIdx(self):
        return random.randint(0,len(self.nodeslots)-1)

    def startNode(self, count):
        if self.nodeslots[count] != None: # Already started
            return
        self.nodeslots[count] = start_node(count, self.options.tmpdir)
        for n in self.nodes:
            connect_nodes(n, count)
        self.nodes.insert(count, self.nodeslots[count])

    def stopNode(self, count):
        tmp = self.nodeslots[count]
        if tmp==None: return  # Already stopped
        stop_node(tmp, count)
        self.nodeslots[count] = None
        try:
            self.nodes.remove(tmp)
        except ValueError:
            pass


    def startAllNodes(self):
        if len(self.nodes) == len(self.nodeslots):
            return
        for count,value in enumerate(self.nodeslots):
            if value == None:
                self.startNode(count)

    def checkMonetaryBase(self, exactMatch = False):

        retry = True
        while retry:
            retry = False
            bals = [ x.getwalletinfo() for x in self.nodes]
            bal = sum([x["balance"] for x in bals])
            unc = sum([x["unconfirmed_balance"] for x in bals])
            im = sum([x["immature_balance"] for x in bals])
            nblocks = self.nodes[0].getblockcount()
            for b in bals:
                if b["syncheight"] != nblocks:
                    logging.info("Wait for wallet sync with block at height: " + str(nblocks))
                    time.sleep(0.5)
                    retry = True
                    break

        print("balances: " + str(bals))
        print("\nTOTAL: " + str(bal+unc+im))
        base = MonetaryBase(nblocks)
        print("block: " + str(nblocks) + "  Money base: " + str(base))
        if exactMatch:
            if bal+unc+im != base:
                print("WARNING: coins lost!!!!\n")

    def run_test (self):

        logging.info("Long test started: initial mining")
        assert MonetaryBase(10) == 10*COINBASE_REWARD
        assert MonetaryBase(160) == 150*COINBASE_REWARD + 9*COINBASE_REWARD/2

        # generate enough blocks so that nodes[0] has a balance
        if True:
            for n in self.nodeslots:
                n.generate(1)
                self.sync_blocks()
            for n in self.nodeslots:
                n.generate(26)
                self.sync_blocks()

        balances = [ x.getbalance() for x in self.nodeslots]
        addresses = [ [x.getnewaddress()] for x in self.nodeslots]

        logging.info("Long test: setup complete")

        count = 0
        while count < 100000:
            count+=1
            if count%10==0: logging.info("Step: " + str(count))

            if count%50==0:
                self.checkMonetaryBase()

            # Stop a node
            if random.randint(0,1000)<5:
                if len(self.nodes)>1:
                    self.stopNode(self.anyNodeIdx())
            # Start a node
            if random.randint(0,1000)<50:
                self.startNode(self.anyNodeIdx())

            # Pay someone a little
            if random.randint(0,1000)<500:  # pay a random node a little
                nodeidx = self.anyLiveNodeIdx()
                addr = random.choice(addresses[nodeidx])
                fromnodeidx = self.anyLiveNodeIdx()
                amt = D(random.uniform(0.0,0.001))
                if amt > DUST:
                    try:
                        txidem = self.nodes[fromnodeidx].sendtoaddress(addr, amt)
                    except JSONRPCException as e:
                        if self.nodes[fromnodeidx].getbalance()+(2*TYPICALFEE) > amt:
                           raise
                        # otherwise ignore, its out of balance
            # multi-pay
            if random.randint(0,1000)<500:  # pay lots of self.nodes a little
                nodeidx = self.anyLiveNodeIdx()
                payTo = {}
                total = D(0)
                for i in range(0,20):
                    addr = random.choice(addresses[nodeidx])
                    fromnodeidx = self.anyLiveNodeIdx()
                    amt = D(random.uniform(0.0,0.001))
                    if amt > DUST:
                        payTo[addr] = amt
                        total += amt
                try:
                    txidem = self.nodes[fromnodeidx].sendmany("", payTo)
                except JSONRPCException as e:
                    if "Transaction too large" in str(e):
                        pass  # just ignore if we tried to spend too many utxos
                    elif self.nodes[fromnodeidx].getbalance()+(20*TYPICALFEE) > total:
                        raise

            # pay a random node a lot
            if random.randint(0,1000)<50:
                nodeidx = self.anyLiveNodeIdx()
                addr = random.choice(addresses[nodeidx])
                fromnodeidx = self.anyLiveNodeIdx()
                bal = self.nodes[fromnodeidx].getbalance()
                amt = D(random.uniform(0.0,float(bal/D(2.0))))
                if amt > DUST:
                    while True:
                        try:
                            txidem = self.nodes[fromnodeidx].sendtoaddress(addr, amt)
                            break
                        except JSONRPCException as e:
                            if "Transaction too large" in str(e):
                                amt = D(amt/2)
                            else:
                                raise
                        except socket.timeout
                            logging.error("Timeout node %d" % fromnodeidx)
            # add a new payment address
            if random.randint(0,1000)<50:
                nodeidx = self.anyLiveNodeIdx()
                newaddr = self.nodes[nodeidx].getnewaddress()
                addresses[nodeidx].append(newaddr)
            # generate a block
            if random.randint(0,1000)<100:
                nodeidx = self.anyLiveNodeIdx()
                logging.info("Building block from: " + str(self.nodes[nodeidx].getmempoolinfo()))
                blkhash = self.nodes[nodeidx].generate(1)[0]
                blk = self.nodes[nodeidx].getblock(blkhash)
                cb = self.nodes[nodeidx].gettransaction(blk['txidem'][0])
                logging.info("coinbase " + str(cb))
                if random.randint(0,1000)<500:
                    self.sync_blocks()            # I have to be fully synced to be sure monetary base should equal wallet sum
                    if len(self.nodes) == len(self.nodeslots):  # Can't check money base is some nodes are off
                        self.checkMonetaryBase(True)  # fee should be realized in CB, so no coins should be lost

            # sync all nodes
            if random.randint(0,1000)<10:
                logging.info("Sync")
                self.sync_blocks()

        self.startAllNodes()
        logging.info("final results")
        for n in nodes:
            logging.info(n.getblockchaininfo())
            logging.info(n.getnetworkinfo())



if __name__ == '__main__':
    MyTest ().main ()

# Create a convenient function for an interactive python debugging session
def Test():
    t = MyTest()
    t.drop_to_pdb = True
    # install ctrl-c handler
    import signal, pdb
    signal.signal(signal.SIGINT, lambda sig, stk: pdb.Pdb().set_trace(stk))
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    logging.getLogger().setLevel(logging.INFO)
    flags = standardFlags()
    flags[0] = '--tmpdir=/tmp/longtest'  # Do not use ramdisk -- will consume it all
    t.main(flags, bitcoinConf, None)
