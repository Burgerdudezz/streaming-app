#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release - UDP-RDT Unit Tests
#

import sys
import os
import unittest
import socket
import struct

# Ensure root path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from streaprous_socket.streaprous_packet_struct import (
    pack_rdt_header,
    unpack_rdt_header,
    compute_checksum,
    rdt_send,
    RDT_HEADER_SIZE
)

class TestUDPRDT(unittest.TestCase):
    
    def test_pack_and_unpack_rdt_header(self):
        seq_num = 123456
        ack_num = 654321
        flags = 0x0001
        checksum = 0xABCD
        rwnd = 65535
        payload_len = 1400
        
        packed = pack_rdt_header(seq_num, ack_num, flags, checksum, rwnd, payload_len)
        self.assertEqual(len(packed), RDT_HEADER_SIZE)
        self.assertEqual(len(packed), 16)
        
        unpacked = unpack_rdt_header(packed)
        self.assertEqual(unpacked['seq_num'], seq_num)
        self.assertEqual(unpacked['ack_num'], ack_num)
        self.assertEqual(unpacked['flags'], flags)
        self.assertEqual(unpacked['checksum'], checksum)
        self.assertEqual(unpacked['rwnd'], rwnd)
        self.assertEqual(unpacked['payload_len'], payload_len)

    def test_compute_internet_checksum(self):
        seq_num = 1
        ack_num = 1
        flags = 0x0002
        rwnd = 1024
        payload = b'Hello UDP-RDT StreapRous'
        
        header_draft = pack_rdt_header(seq_num, ack_num, flags, 0, rwnd, len(payload))
        chk = compute_checksum(header_draft, payload)
        
        self.assertIsInstance(chk, int)
        self.assertTrue(0 <= chk <= 0xffff)
        
        header_final = pack_rdt_header(seq_num, ack_num, flags, chk, rwnd, len(payload))
        total = header_final + payload
        
        if len(total) % 2 == 1:
            total += b'\x00'
            
        s = 0
        for i in range(0, len(total), 2):
            s += struct.unpack('!H', total[i:i+2])[0]
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        self.assertEqual(~s & 0xffff, 0)

    def test_memoryview_fragmentation_and_rdt_send(self):
        class MockUDPSocket:
            def __init__(self):
                self.sent_packets = []
            def sendto(self, packet, addr):
                self.sent_packets.append((packet, addr))
                
        sock = MockUDPSocket()
        large_data = b'B' * 3500
        
        total_sent, next_seq = rdt_send(
            sock, ('127.0.0.1', 9000), large_data,
            seq_num=1000, ack_num=0, flags=0x0001, rwnd=65535, mss=1400
        )
        
        self.assertEqual(total_sent, 3500)
        self.assertEqual(next_seq, 1000 + 3500)
        self.assertEqual(len(sock.sent_packets), 3)
        
        pkt0, addr0 = sock.sent_packets[0]
        self.assertEqual(addr0, ('127.0.0.1', 9000))
        self.assertEqual(len(pkt0), 16 + 1400)
        h0 = unpack_rdt_header(pkt0[:16])
        self.assertEqual(h0['seq_num'], 1000)
        self.assertEqual(h0['payload_len'], 1400)
        self.assertEqual(pkt0[16:], b'B' * 1400)
        
        pkt1, _ = sock.sent_packets[1]
        self.assertEqual(len(pkt1), 16 + 1400)
        h1 = unpack_rdt_header(pkt1[:16])
        self.assertEqual(h1['seq_num'], 1000 + 1400)
        self.assertEqual(h1['payload_len'], 1400)
        
        pkt2, _ = sock.sent_packets[2]
        self.assertEqual(len(pkt2), 16 + 700)
        h2 = unpack_rdt_header(pkt2[:16])
        self.assertEqual(h2['seq_num'], 1000 + 2800)
        self.assertEqual(h2['payload_len'], 700)
        self.assertEqual(pkt2[16:], b'B' * 700)

if __name__ == '__main__':
    unittest.main()
