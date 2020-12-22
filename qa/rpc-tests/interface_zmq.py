#!/usr/bin/env python3
# Copyright (c) 2015-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the ZMQ notification interface."""
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
import struct
from io import BytesIO

from test_framework.test_framework import BitcoinTestFramework
from test_framework.nodemessages import CTransaction
from test_framework.util import *

try:
    import zmq
except ModuleNotFoundError:
    print("zmq module not found")
    print("you need to install it to run this test: 'sudo pip3 install zmq'")
    sys.exit(-1)

class ZMQSubscriber:
    def __init__(self, socket, topic):
        self.sequence = 0
        self.socket = socket
        self.topic = topic
        self.socket.setsockopt(zmq.SUBSCRIBE, self.topic)

    def receive(self):
        tmp = self.socket.recv_multipart()
        topic = tmp[0]
        body = tmp[1]
        # Topic should match the subscriber topic.
        assert_equal(topic, self.topic)

        if len(tmp) >= 3:
            # Sequence should be incremental.
            seq = tmp[2]
            assert_equal(struct.unpack('<I', seq)[-1], self.sequence)
            self.sequence += 1
        return body


class ZMQTest (BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2

    def setup_nodes(self):
        # Initialize ZMQ context and socket.
        # All messages are received in the same socket which means that this
        # test fails if the publishing order changes.
        # Note that the publishing order is not defined in the documentation and
        # is subject to change.
        address = "tcp://127.0.0.1:28342" # ZMQ ports of these test must be unique so multiple tests can be run simultaneously
        self.zmq_context = zmq.Context()
        socket = self.zmq_context.socket(zmq.SUB)
        socket.set(zmq.RCVTIMEO, 60000)
        socket.connect(address)

        # Subscribe to all available topics.
        self.hashblock = ZMQSubscriber(socket, b"hashblock")
        self.hashtx = ZMQSubscriber(socket, b"hashtx")
        self.rawblock = ZMQSubscriber(socket, b"rawblock")
        self.rawtx = ZMQSubscriber(socket, b"rawtx")

        self.extra_args = [["-zmqpub{}={}".format(sub.topic.decode(), address) for sub in [
            self.hashblock, self.hashtx, self.rawblock, self.rawtx]], []]
        ret  = start_nodes(self.num_nodes, self.options.tmpdir, self.extra_args)
        return ret

    def run_test(self):
        try:
            self._zmq_test()
        finally:
            # Destroy the ZMQ context.
            logging.debug("Destroying ZMQ context")
            self.zmq_context.destroy(linger=None)

    def _zmq_test(self):
        num_blocks = 5
        logging.info(
            "Generate {0} blocks (and {0} coinbase txes)".format(num_blocks))
        genhashes = self.nodes[0].generate(num_blocks)
        self.sync_all()

        for x in range(num_blocks):
            # Should receive the coinbase txid.
            txid = self.hashtx.receive()

            # Should receive the coinbase raw transaction.
            hex = self.rawtx.receive()
            tx = CTransaction()
            tx.deserialize(BytesIO(hex))
            tx.calc_sha256()
            assert_equal(tx.hash, txid.hex())

            # Should receive the generated block hash.
            hash = self.hashblock.receive().hex()
            assert_equal(genhashes[x], hash)
            # The block should only have the coinbase txid.
            assert_equal([txid.hex()], self.nodes[1].getblock(hash)["tx"])

            # Should receive the generated raw block.
            block = self.rawblock.receive()
            assert_equal(genhashes[x], hash256(block[:80])[::-1].hex())

        logging.info("Wait for tx from second node")
        payment_txid = self.nodes[1].sendtoaddress(
            self.nodes[0].getnewaddress(), 1.0)
        self.sync_all()

        # Should receive the broadcasted txid.
        txid = self.hashtx.receive()
        assert_equal(payment_txid, txid.hex())

        # Should receive the broadcasted raw transaction.
        hex = self.rawtx.receive()
        assert_equal(payment_txid, hash256(hex)[::-1].hex())


if __name__ == '__main__':
    ZMQTest().main()

def Test():
    flags = standardFlags()
    t = ZMQTest()
    t.drop_to_pdb = True
    t.main(flags)
