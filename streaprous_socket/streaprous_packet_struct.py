import socket
import struct

RDT_HEADER_FORMAT = '!IIHHHH'
RDT_HEADER_SIZE = struct.calcsize(RDT_HEADER_FORMAT)

def pack_rdt_header(seq_num, ack_num, flags, checksum, rwnd, payload_len):
    return struct.pack(RDT_HEADER_FORMAT, seq_num, ack_num, flags, checksum, rwnd, payload_len)

def unpack_rdt_header(header_bytes):
    unpacked = struct.unpack(RDT_HEADER_FORMAT, header_bytes[:RDT_HEADER_SIZE])
    return {
        'seq_num': unpacked[0],
        'ack_num': unpacked[1],
        'flags': unpacked[2],
        'checksum': unpacked[3],
        'rwnd': unpacked[4],
        'payload_len': unpacked[5]
    }

def compute_checksum(header_bytes, payload_bytes=b''):
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

def rdt_send(udp_sock, dest_addr, data, seq_num=0, ack_num=0, flags=0x0001, rwnd=65535, mss=1400):
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data)
    data_mv = memoryview(data)
    total_sent = 0
    current_seq = seq_num
    if len(data_mv) <= mss:
        chunks = [data_mv]
    else:
        chunks = [data_mv[i:i + mss] for i in range(0, len(data_mv), mss)]
    for chunk in chunks:
        chunk_bytes = chunk.tobytes()
        payload_len = len(chunk_bytes)
        draft_header = pack_rdt_header(current_seq, ack_num, flags, 0, rwnd, payload_len)
        real_checksum = compute_checksum(draft_header, chunk_bytes)
        final_header = pack_rdt_header(current_seq, ack_num, flags, real_checksum, rwnd, payload_len)
        packet = final_header + chunk_bytes
        udp_sock.sendto(packet, dest_addr)
        total_sent += payload_len
        current_seq += payload_len
    print(f'[UDP-RDT] Sent {len(chunks)} chunk(s), total {total_sent} bytes, next_seq={current_seq} to {dest_addr}')
    return total_sent, current_seq