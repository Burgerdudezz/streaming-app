#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release - UDP Raw Connection & 3-Way Handshake
#

"""
StreapRous Raw Connection Library (UDP Refactor)
A library for handling UDP-based RDT connections simulating TCP 3-way handshake.
"""

import socket
import struct
import threading
import time
import random
from collections import namedtuple

from .streaprous_packet_struct import (
    SYN, ACK, FIN, DATA, SYN_ACK,
    pack_rdt_header, unpack_rdt_header,
    compute_checksum, chunk_and_pack_data, RDT_HEADER_SIZE,
    rdt_send,
    # TCP Header API (used by streaprous_reliability.py)
    pack_tcp_header, unpack_tcp_header, compute_tcp_checksum
)

# ==========================================
# Import from CO3094 Packet Dispatcher (Raw Socket Receive Infrastructure)
# ==========================================
from .streaprous_packet_dispatcher import (
    start_packet_dispatcher,
    stop_packet_dispatcher,
    get_packet_queue,
    remove_packet_queue,
    _packet_dispatcher_lock,
    _SYN_KEY
)

conn_struct = namedtuple('conn_struct', [
    'client_ip', 'client_port', 'server_ip', 'server_port',
    'state', 'server_seq', 'client_seq', 'expected_final_ack', 'last_activity'
])

connections = {}
connections_lock = threading.Lock()
DEFAULT_INTERFACE_NAME = "127.0.0.1"
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22239

def create_udp_socket(ip: str = "0.0.0.0", port: int = 22239) -> socket.socket:
    """Initialize and bind a standard UDP socket (socket.SOCK_DGRAM)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip, port))
    print(f"[UDP-Connection] Bound UDP socket to {ip}:{port}")
    return sock

def connect_udp_handshake(sock: socket.socket, server_addr: tuple, timeout: float = 2.0, max_retries: int = 3) -> conn_struct:
    """Simulate TCP 3-Way Handshake as Client over UDP."""
    client_seq = random.randint(1000, 10000)
    syn_hdr = pack_rdt_header(client_seq, 0, SYN, 0, 65535, 0)
    syn_pkt = pack_rdt_header(client_seq, 0, SYN, compute_checksum(syn_hdr), 65535, 0)
    
    orig_to = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        server_seq = 0
        for attempt in range(1, max_retries + 1):
            sock.sendto(syn_pkt, server_addr)
            try:
                resp, addr = sock.recvfrom(2048)
                if len(resp) >= RDT_HEADER_SIZE:
                    h = unpack_rdt_header(resp[:RDT_HEADER_SIZE])
                    if (h['flags'] & SYN_ACK) == SYN_ACK and h['ack_num'] == client_seq + 1:
                        server_seq = h['seq_num']
                        break
            except socket.timeout:
                continue
        else:
            raise TimeoutError(f"Handshake failed: No SYN-ACK from {server_addr}")
            
        ack_hdr = pack_rdt_header(client_seq + 1, server_seq + 1, ACK, 0, 65535, 0)
        ack_pkt = pack_rdt_header(client_seq + 1, server_seq + 1, ACK, compute_checksum(ack_hdr), 65535, 0)
        sock.sendto(ack_pkt, server_addr)
        
        local_ip, local_port = sock.getsockname()
        return conn_struct(local_ip, local_port, server_addr[0], server_addr[1],
                           "ESTABLISHED", server_seq + 1, client_seq + 1, server_seq + 1, time.time())
    finally:
        sock.settimeout(orig_to)

def accept_udp_handshake(sock: socket.socket, timeout: float = 5.0) -> tuple:
    """Simulate TCP 3-Way Handshake as Server over UDP."""
    orig_to = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        pkt, client_addr = sock.recvfrom(2048)
        h = unpack_rdt_header(pkt[:RDT_HEADER_SIZE])
        if not (h['flags'] & SYN):
            raise ValueError("Expected SYN packet")
            
        server_seq = random.randint(50000, 90000)
        syn_ack_hdr = pack_rdt_header(server_seq, h['seq_num'] + 1, SYN_ACK, 0, 65535, 0)
        syn_ack_pkt = pack_rdt_header(server_seq, h['seq_num'] + 1, SYN_ACK, compute_checksum(syn_ack_hdr), 65535, 0)
        sock.sendto(syn_ack_pkt, client_addr)
        
        sock.settimeout(2.0)
        ack_pkt, _ = sock.recvfrom(2048)
        ah = unpack_rdt_header(ack_pkt[:RDT_HEADER_SIZE])
        if not (ah['flags'] & ACK) or ah['ack_num'] != server_seq + 1:
            raise ValueError("Invalid final ACK")
            
        server_ip, server_port = sock.getsockname()
        conn = conn_struct(client_addr[0], client_addr[1], server_ip, server_port,
                           "ESTABLISHED", server_seq + 1, h['seq_num'] + 1, server_seq + 1, time.time())
        with connections_lock:
            connections[(client_addr[0], client_addr[1])] = conn
        return conn, client_addr
    finally:
        sock.settimeout(orig_to)

def run_conn_recv(s: socket.socket, conn_info: conn_struct) -> bytes:
    try:
        pkt, addr = s.recvfrom(2048)
        if addr[0] != conn_info.client_ip or addr[1] != conn_info.client_port:
            return b""
        h = unpack_rdt_header(pkt[:RDT_HEADER_SIZE])
        if h['flags'] & FIN:
            with connections_lock:
                connections.pop((conn_info.client_ip, conn_info.client_port), None)
            return b""
        return pkt[RDT_HEADER_SIZE:]
    except socket.timeout:
        return b""

def run_conn_send(s: socket.socket, conn_info: conn_struct, payload: bytes) -> int:
    dest_addr = (conn_info.server_ip, conn_info.server_port)
    sent, _ = rdt_send(s, dest_addr, payload, seq_num=conn_info.server_seq, ack_num=conn_info.client_seq)
    return sent

def close_connection(s: socket.socket, conn_info: conn_struct):
    dest_addr = (conn_info.server_ip, conn_info.server_port)
    fin_hdr = pack_rdt_header(conn_info.server_seq, conn_info.client_seq, FIN, 0, 65535, 0)
    fin_pkt = pack_rdt_header(conn_info.server_seq, conn_info.client_seq, FIN, compute_checksum(fin_hdr), 65535, 0)
    s.sendto(fin_pkt, dest_addr)
    with connections_lock:
        connections.pop((conn_info.client_ip, conn_info.client_port), None)

def close_all_connections():
    with connections_lock:
        connections.clear()


# ==========================================
# TCP/IP Raw Socket Support Functions
# Added for compatibility with streaprous_packet_struct.rdt_send
# and streaprous_reliability.reliable_send
# ==========================================

def checksum(data: bytes) -> int:
    """Compute Internet checksum (RFC 1071)."""
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = struct.unpack('!H', data[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=0, fin=0):
    """Build a 20-byte TCP header with RFC 1071 checksum."""
    flags = (ack << 4) + (syn << 1) + fin
    offset_res = (5 << 4) + 0  # 20 bytes data offset (5 * 4)
    window = 5840
    urg_ptr = 0
    draft_checksum = 0

    # Build a draft (20 byte) header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )

    # Build pseudo-header for checksum
    address_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_temp)
    )

    # Calculate mathematical checksum integer
    tcp_checksum = checksum(address_header + tcp_header_temp)

    # Build the final TCP packet
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )

    return tcp_header


def build_ip_header(src_ip, dest_ip, protocol, payload_len):
    """Build a 20-byte IP header with checksum."""
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len  # IP header + payload

    identification = 0x1234
    flags_fragment = 0x4000
    flags_offset = 0
    ttl = 64
    draft_checksum = 0

    # Build draft header with no checksum
    ip_header_temp = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, draft_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )

    # Calculate the checksum
    ip_checksum = checksum(ip_header_temp)

    # Build the final IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, ip_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )

    return ip_header


def create_raw_socket() -> socket.socket:
    """
    Create a raw socket for TCP protocol. Requires root/admin privileges.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def send_tcp_data_segment(sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, payload, psh=1):
    """
    Build and send a TCP data segment (IP + TCP headers + payload) via raw socket.
    Used by streaprous_reliability.reliable_send.
    """
    tcp_header = build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, ack=1, psh=psh)
    ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
    full_packet = ip_header + tcp_header + payload
    sock.sendto(full_packet, (dest_ip, 0))
    return len(payload)


def accept(sock: socket.socket, timeout: float = 5.0) -> tuple:
    """Accept a connection on a raw socket (simplified)."""
    sock.settimeout(timeout)
    try:
        pkt, addr = sock.recvfrom(65535)
        # Parse IP header to get source
        ihl = (pkt[0] & 0x0F) * 4
        tcp_pkt = pkt[ihl:]
        if len(tcp_pkt) >= 20:
            tcph = struct.unpack('!HHLLBBHHH', tcp_pkt[:20])
            src_port, dst_port, seq, ack_seq, flags = tcph[0], tcph[1], tcph[2], tcph[3], tcph[5]
            # Return connection info
            conn = conn_struct(addr[0], src_port, addr[0], dst_port, "ESTABLISHED", seq, ack_seq, ack_seq, time.time())
            return conn, addr
    except socket.timeout:
        pass
    return None, None






