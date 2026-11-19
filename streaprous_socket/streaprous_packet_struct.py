#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release
#

"""
StreapRous Packet Struct Module
Provides standard TCP header packing/unpacking and RFC 1071 checksum calculation,
used by the raw TCP stack.
"""

import socket
import struct

# ==========================================
# RDT Protocol Constants & Flags
# ==========================================
SYN = 0x02
ACK = 0x10
FIN = 0x01
DATA = 0x08
SYN_ACK = SYN | ACK

from .streaprous_flow_control import RCV_BUF


def pack_tcp_header(src_port, dst_port, seq, ack_seq, offset_res, flags, window=RCV_BUF, checksum=0, urg_ptr=0):
    """
    Stitches a structurally flawless 20-byte TCP header using Network Byte Order (!).
    
    Args:
        src_port     (int): Source port (16-bit)
        dst_port     (int): Destination port (16-bit)
        seq          (int): Sequence number (32-bit)
        ack_seq      (int): Acknowledgement number (32-bit)
        offset_res   (int): Data offset (4 bits) + Reserved (4 bits) (8-bit field total in struct)
        flags        (int): TCP flags (SYN, ACK, FIN, PSH, etc.) (8-bit)
        window       (int): Window size (16-bit)
        checksum     (int): TCP Checksum (16-bit)
        urg_ptr      (int): Urgent pointer (16-bit)
        
    Returns:
        bytes: Packed 20-byte TCP header
    """
    return struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, checksum, urg_ptr
    )


def unpack_tcp_header(tcp_packet_bytes):
    """
    Unpacks a 20-byte TCP header into a dictionary of fields.
    
    Args:
        tcp_packet_bytes (bytes or memoryview): Raw packet bytes starting with TCP header
        
    Returns:
        dict: Dictionary containing all unpacked TCP header fields
    """
    tcph = struct.unpack('!HHLLBBHHH', tcp_packet_bytes[:20])
    return {
        'src_port': tcph[0],
        'dst_port': tcph[1],
        'seq': tcph[2],
        'ack_seq': tcph[3],
        'offset_res': tcph[4],
        'flags': tcph[5],
        'window': tcph[6],
        'checksum': tcph[7],
        'urg_ptr': tcph[8],
        'data_offset': (tcph[4] >> 4) * 4  # Header length in bytes
    }


def compute_tcp_checksum(src_ip, dst_ip, tcp_header_bytes, payload_bytes=b""):
    """
    Computes standard TCP Checksum according to RFC 1071, supporting Pseudo-IP Header.
    
    Pseudo-IP Header (12 bytes):
      - Source IP address (4 bytes)
      - Destination IP address (4 bytes)
      - Reserved (1 byte, 0)
      - Protocol (1 byte, 6 for TCP)
      - TCP Length (2 bytes, len(tcp_header_bytes) + len(payload_bytes))
      
    Args:
        src_ip           (str): Source IP address (e.g., "127.0.0.1")
        dst_ip           (str): Destination IP address (e.g., "127.0.0.1")
        tcp_header_bytes (bytes): TCP header bytes (with checksum set to 0)
        payload_bytes    (bytes or memoryview): TCP payload data
        
    Returns:
        int: 16-bit computed checksum value
    """
    tcp_len = len(tcp_header_bytes) + len(payload_bytes)
    
    # Build Pseudo-IP Header
    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_len
    )
    
    # Combine pseudo header, TCP header (with zero checksum), and payload
    if isinstance(payload_bytes, memoryview):
        payload_bytes = payload_bytes.tobytes()
        
    total_msg = pseudo_header + tcp_header_bytes + payload_bytes
    
    # RFC 1071 Checksum Algorithm: One's complement sum of 16-bit words
    if len(total_msg) % 2 == 1:
        total_msg += b'\x00'
        
    s = 0
    for i in range(0, len(total_msg), 2):
        w = struct.unpack('!H', total_msg[i:i+2])[0]
        s += w
        
    # Fold 32-bit sum to 16-bit
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    
    # One's complement
    return ~s & 0xffff
