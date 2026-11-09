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


def rdt_send(sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, data, auto_chunk=True, mss=1460, flags=0x18, window=5840):
    """
    Flexible Reliable Data Transfer (RDT) send function with automatic data fragmentation
    and memory optimization using memoryview.
    
    Args:
        sock      (socket.socket): Raw socket instance
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


# ==========================================
# UDP-RDT Packet Struct Aliases & Helpers
# ==========================================
RDT_HEADER_SIZE = 16


def pack_rdt_header(seq_num, ack_num, flags, checksum=0, window=65535, payload_len=0):
    """
    Stitches a 16-byte RDT header for UDP encapsulation:
      - seq_num (4 bytes, unsigned int)
      - ack_num (4 bytes, unsigned int)
      - flags   (2 bytes, unsigned short)
      - window  (2 bytes, unsigned short)
      - checksum(2 bytes, unsigned short)
      - payload_len (2 bytes, unsigned short) -> Total 16 bytes
    """
    return struct.pack('!IIHHHH', seq_num, ack_num, flags, window, checksum, payload_len)


def unpack_rdt_header(header_bytes):
    """
    Unpacks a 16-byte RDT header into a dictionary.
    """
    unpacked = struct.unpack('!IIHHHH', header_bytes[:16])
    return {
        'seq_num': unpacked[0],
        'ack_num': unpacked[1],
        'flags': unpacked[2],
        'window': unpacked[3],
        'checksum': unpacked[4],
        'payload_len': unpacked[5]
    }


def compute_checksum(packet_bytes):
    """
    Computes RFC 1071 internet checksum for RDT packet bytes.
    """
    if isinstance(packet_bytes, memoryview):
        packet_bytes = packet_bytes.tobytes()
    if len(packet_bytes) % 2 == 1:
        packet_bytes += b'\x00'
    s = 0
    for i in range(0, len(packet_bytes), 2):
        w = struct.unpack('!H', packet_bytes[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def chunk_and_pack_data(data, start_seq=1, mss=1400):
    """
    Chunks binary data using memoryview and packs each chunk with RDT header.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
    
    data_mv = memoryview(data)
    packets = []
    current_seq = start_seq
    
    if len(data_mv) == 0:
        hdr = pack_rdt_header(current_seq, 0, DATA, 0, 65535, 0)
        chk = compute_checksum(hdr)
        hdr = pack_rdt_header(current_seq, 0, DATA, chk, 65535, 0)
        return [hdr]
        
    for i in range(0, len(data_mv), mss):
        chunk = data_mv[i:i + mss]
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        
        # Build header with checksum = 0
        draft_hdr = pack_rdt_header(current_seq, 0, DATA, 0, 65535, payload_len)
        chk = compute_checksum(draft_hdr + chunk_bytes)
        final_hdr = pack_rdt_header(current_seq, 0, DATA, chk, 65535, payload_len)
        
        packets.append(final_hdr + chunk_bytes)
        current_seq += payload_len
        
    return packets


def rdt_send(sock, *args, **kwargs):
    """
    Sends data using UDP-RDT packets with fragmentation.
    Supports both new signature (sock, dest_addr, data, seq_num=1, ack_num=0, mss=1400)
    and legacy signature (sock, src_ip, dest_ip, src_port, dst_port, seq=1, ack_seq=0, data, auto_chunk=True, mss=1460).
    """
    # Legacy mode detection: 5 positional args after sock (src_ip, dest_ip, src_port, dst_port, data)
    # or keyword args with src_ip, dest_ip, src_port, dst_port
    src_ip = kwargs.get('src_ip')
    dest_ip = kwargs.get('dest_ip')
    src_port = kwargs.get('src_port')
    dst_port = kwargs.get('dst_port')
    
    # Also check positional args for legacy mode
    if len(args) >= 5:
        # Legacy positional: sock, src_ip, dest_ip, src_port, dst_port, [data], ...
        # Check if args[0] looks like an IP and args[1] looks like an IP
        if isinstance(args[0], str) and isinstance(args[1], str) and '.' in args[0] and '.' in args[1]:
            src_ip = args[0]
            dest_ip = args[1]
            src_port = args[2]
            dst_port = args[3]
            # data might be args[4] or in kwargs
            if 'data' in kwargs:
                data = kwargs['data']
            elif len(args) > 4:
                data = args[4]
            else:
                data = b''
            # Legacy seq/ack
            seq_num = kwargs.get('seq', kwargs.get('seq_num', 1))
            ack_num = kwargs.get('ack_seq', kwargs.get('ack_num', 0))
            auto_chunk = kwargs.get('auto_chunk', True)
            mss = kwargs.get('mss', 1460)
            
            # Legacy mode: uses Raw socket with IP/TCP headers
            from streaprous_socket.streaprous_raw_connection import build_ip_header
            
            if not isinstance(data, (bytes, bytearray, memoryview)):
                data = data.encode('utf-8') if isinstance(data, str) else bytes(data)
                
            data_mv = memoryview(data)
            total_sent = 0
            current_seq = seq_num
            
            if not auto_chunk or len(data_mv) <= mss:
                chunks = [data_mv]
            else:
                chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
                
            offset_res = (5 << 4) + 0
            urg_ptr = 0
            flags = 0x18  # PSH + ACK
            window = 5840
            
            for chunk in chunks:
                chunk_bytes = chunk.tobytes()
                
                # 1. Build draft TCP header with checksum = 0
                draft_tcp_header = pack_tcp_header(
                    src_port, dst_port, current_seq, ack_num,
                    offset_res, flags, window, 0, urg_ptr
                )
                
                # 2. Compute RFC 1071 Checksum with Pseudo-IP Header
                tcp_checksum = compute_tcp_checksum(src_ip, dest_ip, draft_tcp_header, chunk_bytes)
                
                # 3. Build final TCP header with valid checksum
                tcp_header = pack_tcp_header(
                    src_port, dst_port, current_seq, ack_num,
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
    
    # New UDP-RDT mode: sock, dest_addr, data, seq_num=1, ack_num=0, mss=1400
    # Parse positional args
    if len(args) >= 2:
        dest_addr = args[0]
        data = args[1]
    else:
        dest_addr = kwargs.get('dest_addr')
        data = kwargs.get('data')
    
    seq_num = kwargs.get('seq_num', kwargs.get('seq', 1))
    ack_num = kwargs.get('ack_num', kwargs.get('ack_seq', 0))
    mss = kwargs.get('mss', 1400)
    
    packets = chunk_and_pack_data(data, start_seq=seq_num, mss=mss)
    total_sent = 0
    for pkt in packets:
        sock.sendto(pkt, dest_addr)
        total_sent += len(pkt) - RDT_HEADER_SIZE
    return total_sent, seq_num + total_sent

