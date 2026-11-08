#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release - UDP-RDT Handshake Unit Tests
#

import sys
import os
import unittest
import socket
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from streaprous_socket.streaprous_raw_connection import (
    create_udp_socket,
    connect_udp_handshake,
    accept_udp_handshake,
    close_connection,
    run_conn_recv,
    run_conn_send,
    conn_struct
)
from streaprous_socket.streaprous_packet_struct import (
    SYN, ACK, FIN, DATA, SYN_ACK,
    pack_rdt_header, unpack_rdt_header, compute_checksum,
    chunk_and_pack_data, rdt_send, RDT_HEADER_SIZE
)

class TestUDPHandshake(unittest.TestCase):
    """Test suite for UDP 3-Way Handshake and packet struct operations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.server_ip = "127.0.0.1"
        self.server_port = 9001
        self.client_ip = "127.0.0.1"
        self.client_port = 9002
    
    def test_chunk_and_pack_data_basic(self):
        """Test chunking and packing of small data."""
        data = b"Hello UDP-RDT"
        packets = chunk_and_pack_data(data, start_seq=1000, mss=1400)
        
        self.assertEqual(len(packets), 1)
        self.assertEqual(len(packets[0]), RDT_HEADER_SIZE + len(data))
        
        hdr = unpack_rdt_header(packets[0][:RDT_HEADER_SIZE])
        self.assertEqual(hdr['seq_num'], 1000)
        self.assertEqual(hdr['flags'], DATA)
        self.assertEqual(hdr['payload_len'], len(data))
        self.assertEqual(packets[0][RDT_HEADER_SIZE:], data)
        
        total = packets[0]
        if len(total) % 2 == 1:
            total += b'\x00'
        s = 0
        for i in range(0, len(total), 2):
            s += (total[i] << 8) + total[i+1]
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        self.assertEqual(~s & 0xffff, 0)
    
    def test_chunk_and_pack_data_fragmentation(self):
        """Test chunking and packing of large data across multiple chunks."""
        data = b'B' * 3500
        packets = chunk_and_pack_data(data, start_seq=1000, mss=1400)
        
        self.assertEqual(len(packets), 3)
        self.assertEqual(len(packets[0]), 16 + 1400)
        
        h0 = unpack_rdt_header(packets[0][:16])
        self.assertEqual(h0['seq_num'], 1000)
        self.assertEqual(h0['payload_len'], 1400)
        
        h1 = unpack_rdt_header(packets[1][:16])
        self.assertEqual(h1['seq_num'], 1000 + 1400)
        self.assertEqual(h1['payload_len'], 1400)
        
        h2 = unpack_rdt_header(packets[2][:16])
        self.assertEqual(h2['seq_num'], 1000 + 2800)
        self.assertEqual(h2['payload_len'], 700)
        
        total_payload = b''.join(p[RDT_HEADER_SIZE:] for p in packets)
        self.assertEqual(total_payload, data)
        
        for pkt in packets:
            total = pkt
            if len(total) % 2 == 1:
                total += b'\x00'
            s = 0
            for i in range(0, len(total), 2):
                s += (total[i] << 8) + total[i+1]
            s = (s >> 16) + (s & 0xffff)
            s += (s >> 16)
            self.assertEqual(~s & 0xffff, 0)
    
    def test_handshake_flags(self):
        """Test flag constants and combinations."""
        self.assertEqual(SYN, 0x02)
        self.assertEqual(ACK, 0x10)
        self.assertEqual(FIN, 0x01)
        self.assertEqual(DATA, 0x08)
        self.assertEqual(SYN_ACK, SYN | ACK)
    
    def test_3way_handshake_localhost(self):
        """Test complete 3-way handshake over localhost."""
        server_sock = create_udp_socket(self.server_ip, self.server_port)
        client_sock = create_udp_socket(self.client_ip, self.client_port)
        
        server_result = {}
        
        def server_thread():
            try:
                conn, client_addr = accept_udp_handshake(server_sock, timeout=10.0)
                server_result['conn'] = conn
                server_result['client_addr'] = client_addr
            except Exception as e:
                server_result['error'] = e
        
        server_t = threading.Thread(target=server_thread)
        server_t.start()
        time.sleep(0.3)
        
        try:
            client_conn = connect_udp_handshake(client_sock, (self.server_ip, self.server_port), timeout=2.0, max_retries=3)
            server_t.join(timeout=5.0)
            
            self.assertEqual(client_conn.state, "ESTABLISHED")
            self.assertEqual(client_conn.server_ip, self.server_ip)
            self.assertEqual(client_conn.server_port, self.server_port)
            
            self.assertIn('conn', server_result)
            server_conn = server_result['conn']
            self.assertEqual(server_conn.state, "ESTABLISHED")
            self.assertEqual(server_conn.client_ip, self.client_ip)
            self.assertEqual(server_conn.client_port, self.client_port)
            
            self.assertEqual(client_conn.client_seq, server_conn.client_seq)
            self.assertEqual(client_conn.server_seq, server_conn.server_seq)
            
        finally:
            close_connection(client_sock, client_conn)
            close_connection(server_sock, server_result['conn'])
            server_sock.close()
            client_sock.close()
    
    def test_rdt_send_receive(self):
        """Test RDT send and receive after handshake."""
        server_sock = create_udp_socket(self.server_ip, self.server_port)
        client_sock = create_udp_socket(self.client_ip, self.client_port)
        
        server_result = {}
        
        def server_thread():
            conn, _ = accept_udp_handshake(server_sock, timeout=10.0)
            server_result['conn'] = conn
            data = run_conn_recv(server_sock, conn)
            server_result['received'] = data
        
        server_t = threading.Thread(target=server_thread)
        server_t.start()
        time.sleep(0.3)
        
        try:
            client_conn = connect_udp_handshake(client_sock, (self.server_ip, self.server_port))
            test_data = b"Test RDT Data Payload"
            sent = run_conn_send(client_sock, client_conn, test_data)
            self.assertEqual(sent, len(test_data))
            
            server_t.join(timeout=5.0)
            self.assertEqual(server_result.get('received'), test_data)
            
        finally:
            if 'conn' in server_result:
                close_connection(server_sock, server_result['conn'])
            close_connection(client_sock, client_conn)
            server_sock.close()
            client_sock.close()
    
    def test_handshake_timeout_retry(self):
        """Test that client retries on timeout."""
        server_sock = create_udp_socket(self.server_ip, self.server_port)
        client_sock = create_udp_socket(self.client_ip, self.client_port)
        
        with self.assertRaises(TimeoutError):
            connect_udp_handshake(client_sock, (self.server_ip, self.server_port), 
                                  timeout=0.3, max_retries=2)
        
        client_sock.close()
        server_sock.close()

if __name__ == '__main__':
    unittest.main()
