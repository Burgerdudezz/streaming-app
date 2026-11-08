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

RDT_HEADER_FORMAT = '!IIHHHH'
RDT_HEADER_SIZE = struct.calcsize(RDT_HEADER_FORMAT)

def pack_rdt_header(seq_num: int, ack_num: int, flags: int, checksum: int, rwnd: int, payload_len: int) -> bytes:
    """Pack RDT 16-byte header using Big-Endian format !IIHHHH."""
    return struct.pack(RDT_HEADER_FORMAT, seq_num, ack_num, flags, checksum, rwnd, payload_len)

def unpack_rdt_header(header_bytes: bytes) -> dict:
    """Unpack 16-byte RDT header into a Python dictionary."""
    unpacked = struct.unpack(RDT_HEADER_FORMAT, header_bytes[:RDT_HEADER_SIZE])
    return {
        'seq_num': unpacked[0],
        'ack_num': unpacked[1],
        'flags': unpacked[2],
        'checksum': unpacked[3],
        'rwnd': unpacked[4],
        'payload_len': unpacked[5]
    }

def compute_checksum(header_bytes: bytes, payload_bytes=b'') -> int:
    """
    Compute 16-bit Internet Checksum (RFC 1071) over header and payload.
    Automatically pads with \x00 if total length is odd.
    """
    if isinstance(payload_bytes, memoryview):
        payload_bytes = payload_bytes.tobytes()
    packet = header_bytes + payload_bytes
    if len(packet) % 2 == 1:
        packet += b'\x00'
    checksum = 0
    for i in range(0, len(packet), 2):
        word = (packet[i] << 8) + packet[i+1]
        checksum += word
    while (checksum >> 16) > 0:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return ~checksum & 0xffff

def chunk_and_pack_data(data, start_seq: int, mss: int = 1400) -> list:
    """
    Chunk large data using zero-copy memoryview and pack each chunk into 
    complete RDT packets (Header + Payload) with correct checksums.
    
    Args:
        data: str, bytes, bytearray, or memoryview to be chunked.
        start_seq (int): Initial sequence number.
        mss (int): Maximum Segment Size (default: 1400 bytes).
        
    Returns:
        list of bytes: List of complete RDT packets ready for queueing/sending.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data)
        
    data_mv = memoryview(data)
    if len(data_mv) <= mss:
        chunks = [data_mv]
    else:
        chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
        
    packets = []
    current_seq = start_seq
    rwnd = 65535
    flags = DATA
    
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        draft_header = pack_rdt_header(current_seq, 0, flags, 0, rwnd, payload_len)
        chksum = compute_checksum(draft_header, chunk_bytes)
        final_header = pack_rdt_header(current_seq, 0, flags, chksum, rwnd, payload_len)
        packets.append(final_header + chunk_bytes)
        current_seq += payload_len
        
    return packets

def rdt_send(udp_sock, dest_addr, data, seq_num=0, ack_num=0, flags=DATA, rwnd=65535, mss=1400):
    """
    Send data reliably over UDP using chunking and checksum calculation.
    """
    packets = chunk_and_pack_data(data, seq_num, mss)
    total_sent = 0
    current_seq = seq_num
    
    for pkt in packets:
        header_bytes = pkt[:RDT_HEADER_SIZE]
        payload_bytes = pkt[RDT_HEADER_SIZE:]
        payload_len = len(payload_bytes)
        
        udp_sock.sendto(pkt, dest_addr)
        total_sent += payload_len
        current_seq += payload_len
        
    print(f'[UDP-RDT] Sent {len(packets)} chunk(s), total {total_sent} bytes, next_seq={current_seq} to {dest_addr}')
    return total_sent, current_seq
