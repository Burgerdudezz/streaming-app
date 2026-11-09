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
StreapRous Packet Struct & Reliability Module
Provides standard TCP header packing/unpacking, RFC 1071 checksum calculation,
and efficient memoryview-based rdt_send data fragmentation.
"""

import socket
import struct
import random

# ==========================================
# RDT Protocol Constants & Flags
# ==========================================
SYN = 0x02
ACK = 0x10
FIN = 0x01
DATA = 0x08
SYN_ACK = SYN | ACK


def pack_tcp_header(src_port, dst_port, seq, ack_seq, offset_res, flags, window, checksum, urg_ptr):
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





# ==========================================
# Backward Compatibility: Old RDT Header API (16-byte format)
# Used by streaprous_raw_connection.py and tests
# ==========================================

RDT_HEADER_SIZE = 16

def pack_rdt_header(seq_num, ack_num, flags, checksum, window, payload_len):
    """
    Pack a 16-byte RDT header (backward compatible format).
    
    Args:
        seq_num (int): Sequence number (32-bit)
        ack_num (int): Acknowledgement number (32-bit)
        flags (int): Flags (16-bit)
        checksum (int): Checksum (16-bit)
        window (int): Window size (16-bit)
        payload_len (int): Payload length (16-bit)
        
    Returns:
        bytes: 16-byte packed RDT header
    """
    return struct.pack('!LLHHHH', seq_num, ack_num, flags, checksum, window, payload_len)


def unpack_rdt_header(header_bytes):
    """
    Unpack a 16-byte RDT header into a dictionary.
    
    Args:
        header_bytes (bytes): 16-byte RDT header
        
    Returns:
        dict: Dictionary with seq_num, ack_num, flags, checksum, window, payload_len
    """
    if len(header_bytes) < RDT_HEADER_SIZE:
        raise ValueError(f"Header too short: expected {RDT_HEADER_SIZE} bytes, got {len(header_bytes)}")
    
    seq_num, ack_num, flags, checksum, window, payload_len = struct.unpack('!LLHHHH', header_bytes[:RDT_HEADER_SIZE])
    return {
        'seq_num': seq_num,
        'ack_num': ack_num,
        'flags': flags,
        'checksum': checksum,
        'window': window,
        'payload_len': payload_len
    }


def compute_checksum(data):
    """
    Compute Internet checksum (RFC 1071) for backward compatibility.
    
    Args:
        data (bytes): Data to compute checksum for
        
    Returns:
        int: 16-bit checksum
    """
    if len(data) % 2 == 1:
        data += b'\x00'
    
    s = 0
    for i in range(0, len(data), 2):
        w = struct.unpack('!H', data[i:i+2])[0]
        s += w
    
    # Fold 32-bit sum to 16-bit
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    
    # One's complement
    return ~s & 0xffff


def chunk_and_pack_data(data, start_seq=0, mss=1400):
    """
    Chunk data and pack into RDT packets (backward compatible).
    
    Args:
        data (bytes): Data to chunk and pack
        start_seq (int): Starting sequence number
        mss (int): Maximum segment size
        
    Returns:
        list: List of packed packets (header + payload)
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
    
    data_mv = memoryview(data)
    packets = []
    current_seq = start_seq
    
    chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        
        # Build header with zero checksum
        header = pack_rdt_header(current_seq, 0, DATA, 0, 65535, payload_len)
        
        # Compute checksum over header + payload
        checksum = compute_checksum(header + chunk_bytes)
        
        # Build final header with correct checksum
        header = pack_rdt_header(current_seq, 0, DATA, checksum, 65535, payload_len)
        
        packets.append(header + chunk_bytes)
        current_seq += payload_len
    
    return packets


# Backward compatible rdt_send with old API (used by streaprous_raw_connection.py)
def rdt_send(sock, arg1, arg2, arg3=None, arg4=None, *args, **kwargs):
    """
    Flexible RDT send function supporting both old UDP API and new raw socket API.
    
    Old UDP API (backward compatible):
        rdt_send(sock, dest_addr, data, seq_num=0, ack_num=0)
        
    New Raw Socket API (for TCP-style):
        rdt_send(sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, data, 
                 auto_chunk=True, mss=1460, flags=0x18, window=5840)
    """
    # Check if this is the new raw socket API:
    # arg1 is src_ip (str), arg2 is dest_ip (str), arg3 is src_port (int), etc.
    if isinstance(arg1, str) and isinstance(arg2, str) and isinstance(arg3, int):
        src_ip = arg1
        dest_ip = arg2
        src_port = arg3
        dst_port = arg4
        seq = kwargs.pop('seq', 0)
        ack_seq = kwargs.pop('ack_seq', 0)
        data = kwargs.pop('data', None)
        if data is None and args:
            data = args[0]
            args = args[1:]
        return _rdt_send_raw(sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, data, *args, **kwargs)
    
    # Otherwise, old UDP API
    dest_addr = arg1
    data = arg2
    seq_num = arg3 if arg3 is not None else kwargs.get('seq_num', 0)
    ack_num = arg4 if arg4 is not None else kwargs.get('ack_num', 0)
    
    dest_ip, dest_port = dest_addr
    
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
    
    # Build RDT header (16 bytes)
    payload_len = len(data)
    header = pack_rdt_header(seq_num, ack_num, DATA, 0, 65535, payload_len)
    checksum_val = compute_checksum(header + data)
    header = pack_rdt_header(seq_num, ack_num, DATA, checksum_val, 65535, payload_len)
    
    packet = header + data
    sock.sendto(packet, dest_addr)
    
    return len(data), seq_num + payload_len


def _rdt_send_raw(sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, data, auto_chunk=True, mss=1460, flags=0x18, window=5840):
    """
    New TCP-style RDT send for raw sockets with IP+TCP headers.
    
    Args:
        sock      (socket.socket): Raw socket instance (SOCK_RAW)
        src_ip    (str): Source IP address
        dest_ip   (str): Destination IP address
        src_port  (int): Source port
        dst_port  (int): Destination port
        seq       (int): Initial sequence number
        ack_seq   (int): Acknowledgement number
        data      (bytes or bytearray): Data payload to transmit
        auto_chunk(bool): If True, automatically fragment data into mss-sized chunks
        mss       (int): Maximum Segment Size (default: 1460 bytes)
        flags     (int): TCP flags (default: 0x18 -> PSH + ACK)
        window    (int): TCP window size (default: 5840)
        
    Returns:
        tuple: (total_sent, next_seq)
    """
    from streaprous_socket.streaprous_raw_connection import build_ip_header
    
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
        
    data_mv = memoryview(data)
    total_sent = 0
    current_seq = seq
    
    if not auto_chunk or len(data_mv) <= mss:
        chunks = [data_mv]
    else:
        chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
        
    offset_res = (5 << 4) + 0
    urg_ptr = 0
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        
        # 1. Build draft TCP header with checksum = 0
        draft_tcp_header = pack_tcp_header(
            src_port, dst_port, current_seq, ack_seq,
            offset_res, flags, window, 0, urg_ptr
        )
        
        # 2. Compute RFC 1071 Checksum with Pseudo-IP Header
        tcp_checksum = compute_tcp_checksum(src_ip, dest_ip, draft_tcp_header, chunk_bytes)
        
        # 3. Build final TCP header with valid checksum
        tcp_header = pack_tcp_header(
            src_port, dst_port, current_seq, ack_seq,
            offset_res, flags, window, tcp_checksum, urg_ptr
        )
        
        # 4. Build IP header
        ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(chunk_bytes))
        
        # 5. Assemble full packet
        full_packet = ip_header + tcp_header + chunk_bytes
        
        # 6. Transmit via Raw Socket
        sock.sendto(full_packet, (dest_ip, 0))
        
        total_sent += len(chunk_bytes)
        current_seq += len(chunk_bytes)
    
    print(f"[Streap_RDT] Sent {len(chunks)} chunk(s), total {total_sent} bytes, next_seq={current_seq}")
    return total_sent, current_seq

