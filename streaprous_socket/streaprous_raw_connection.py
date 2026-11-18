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
StreapRous Raw Connection Library
A library for handling TCP connections with raw sockets.
Provides connection management, reliable send/receive, flow control,
and congestion control using raw sockets.
"""

import secrets
import socket
import struct
import sys
import threading
import time
import queue
from collections import namedtuple
import netifaces

from .transport_control import (
    CubicController,
    FlowControlWindow,
    ReceiveReorderBuffer,
    ReliableSendBuffer,
    RttEstimator,
    seq_add,
    seq_le,
)

from .streaprous_packet_dispatcher import (
    start_packet_dispatcher,
    get_packet_queue,
    remove_packet_queue,
    _SYN_KEY,
)

TCP_MSS = 1400
RECEIVE_CAPACITY = 64 * 1024

# Connection structure
conn_struct = namedtuple('conn_struct', [
    'client_ip',
    'client_port',
    'server_ip',
    'server_port',
    'state',
    'server_seq',
    'client_seq',
    'expected_final_ack',
    'last_activity'
])
ConnectionInfo = conn_struct

# Global table to manage multiple connections: { (client_ip, client_port): conn_struct }
connections = {}
connections_lock = threading.Lock()

# Per-connection TCP control blocks (ReliableSendBuffer, ReceiveReorderBuffer, Flow, Congestion, RTT)
_conn_states = {}

# Management structure to serialize the 3-way handshake
handshake_lock = threading.Lock()
handshake_in_progress = {}
_cleanup_thread = None
_cleanup_lock = threading.Lock()

# Default raw port listener
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22239
DEFAULT_INTERFACE_NAME = "eth0"


def _generate_isn() -> int:
    """Generate a random 32-bit Initial Sequence Number (RFC 9293)."""
    return secrets.randbelow(0xFFFFFFFE) + 1


def _touch_connection(client_key):
    """Refresh last_activity timestamp so active transfers are never timed out."""
    with connections_lock:
        session = connections.get(client_key)
        if session is not None:
            connections[client_key] = session._replace(last_activity=time.time())


def _advertised_window(st) -> int:
    """Receive window after accounting for both reorder storage and app-unread bytes."""
    receiver = st["receiver"]
    occupied = receiver.buffered_bytes + len(st["unread"])
    return max(0, receiver.capacity - occupied)


def _receive_payload(st, seq: int, payload: bytes) -> bytes:
    """Receive in-order stream bytes without exceeding the total per-connection capacity.

    ReceiveReorderBuffer drains contiguous bytes from its own ready area on each
    receive(), so those bytes are transferred to the application-facing unread
    buffer and must continue consuming receive-window capacity until the app reads.
    Caller must hold st["lock"].
    """
    if not payload:
        return b""
    receiver = st["receiver"]
    original_capacity = receiver.capacity
    receiver.capacity = max(0, original_capacity - len(st["unread"]))
    try:
        ready = receiver.receive(seq, payload)
    finally:
        receiver.capacity = original_capacity
    if ready:
        st["unread"].extend(ready)
    return ready


def _take_unread(st) -> bytes:
    """Drain bytes already accepted from the peer for the application."""
    with st["lock"]:
        ready = bytes(st["unread"])
        st["unread"].clear()
        # Also drain any bytes that remain in the reorder buffer's ready area.
        pending_ready = st["receiver"].read()
        if pending_ready:
            ready += pending_ready
    return ready


def _valid_final_ack(client_seq: int, client_syn_seq: int,
                     ack_num: int, expected_ack: int) -> bool:
    """Validate both sequence and acknowledgement numbers of the 3rd handshake leg."""
    return client_seq == seq_add(client_syn_seq, 1) and ack_num == expected_ack


def _ensure_cleanup_thread():
    """Start exactly one daemon cleanup loop for stale connection state."""
    global _cleanup_thread
    with _cleanup_lock:
        if _cleanup_thread is None or not _cleanup_thread.is_alive():
            _cleanup_thread = threading.Thread(
                target=clean_expired_connections,
                daemon=True,
                name="streaprous-connection-cleanup",
            )
            _cleanup_thread.start()


def _remove_connection(client_key):
    """Clean up connection metadata, transport state, and dispatcher queue."""
    with connections_lock:
        connections.pop(client_key, None)
        _conn_states.pop(client_key, None)
    remove_packet_queue(client_key)


def register_keep_port_alive(listen_ip="0.0.0.0", listen_port=22239, retry_interval=10):
    """Periodically register and maintain TCP port without accepting on standard socket."""
    def _keep_alive():
        print(f"[Streap_raw] Start port keep-alive thread for {listen_ip}:{listen_port}")
        attempt = 0
        while True:
            attempt += 1
            standard_sock = None
            try:
                standard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                standard_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                standard_sock.bind((listen_ip, listen_port))
                standard_sock.listen(0)
                print(f"[Streap_raw] register_keep_port_alive: Done port {listen_port} registration.")
                while True:
                    time.sleep(3600)
            except Exception as e:
                print(f"[Streap_raw] register_keep_port_alive: Fail port registration with error {e}")
            finally:
                if standard_sock:
                    standard_sock.close()
            time.sleep(retry_interval)

    thread = threading.Thread(target=_keep_alive, daemon=True, name=f"port-keep-alive-{listen_port}")
    thread.start()
    return thread


def checksum(msg):
    """Calculates an RFC 1071 Internet checksum and returns an integer."""
    if len(msg) % 2 == 1:
        msg += b'\x00'
    s = 0
    for i in range(0, len(msg), 2):
        w = struct.unpack('!H', msg[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff


def build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=0, fin=0, window=5840):
    """Stitches a structurally flawless 20-byte TCP header."""
    flags = (ack << 4) + (syn << 1) + fin
    offset_res = (5 << 4) + 0
    window = max(0, min(65535, int(window)))
    urg_ptr = 0
    draft_checksum = 0

    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    address_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_temp)
    )
    tcp_checksum = checksum(address_header + tcp_header_temp)
    return struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )


def build_ip_header(src_ip, dest_ip, protocol, payload_len):
    """Builds a structurally flawless 20-byte IP header."""
    version_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    identification = 0x1234
    flags_offset = 0
    ttl = 64
    draft_checksum = 0

    ip_header_temp = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, draft_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )
    ip_checksum = checksum(ip_header_temp)
    return struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_len, identification,
        flags_offset, ttl, protocol, ip_checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip)
    )


def send_tcp_data_segment(s, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, payload, window=5840):
    """Assembles and transmits a single TCP segment containing data payload."""
    flags = 0x18  # PSH + ACK
    offset_res = (5 << 4) + 0
    window = max(0, min(65535, int(window)))
    urg_ptr = 0
    draft_checksum = 0

    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    tcp_len = len(tcp_header_temp) + len(payload)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, tcp_len
    )
    tcp_checksum = checksum(pseudo + tcp_header_temp + payload)
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )
    ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
    full_packet = ip_header + tcp_header + payload
    s.sendto(full_packet, (dest_ip, 0))
    return len(payload)


def _decode_packet(packet: bytes):
    """Extract TCP fields and payload from an IPv4/TCP raw packet."""
    if len(packet) < 20 or (packet[0] >> 4) != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + 20 or packet[9] != 6:
        return None
    tcp = packet[ihl:]
    data_offset = (tcp[12] >> 4) * 4
    if data_offset < 20 or len(tcp) < data_offset:
        return None
    src_port, dst_port, seq, ack = struct.unpack('!HHII', tcp[:12])
    flags = tcp[13]
    window = struct.unpack('!H', tcp[14:16])[0]
    return src_port, dst_port, seq, ack, flags, window, tcp[data_offset:]


def clean_expired_connections(timeout=60):
    """Background thread to clean up stale or timed-out connections."""
    while True:
        time.sleep(10)
        now = time.time()
        with connections_lock:
            expired = [k for k, session in connections.items() if now - session.last_activity > timeout]
            for k in expired:
                print(f"[Streap_raw] clean_expired_connections: Session [{k[0]}:{k[1]}] timed out ({timeout}s). Removing.")
                del connections[k]
                _conn_states.pop(k, None)
        for k in expired:
            remove_packet_queue(k)


def create_raw_socket(interface_name: str = "lo0") -> socket.socket:
    """Create a raw socket for TCP protocol. Requires root privileges."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("[Streap_raw] Create raw socket binding for 0.0.0.0 listening")
        return sock
    except PermissionError:
        print("Error: Root privileges required (sudo).")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating raw socket: {e}")
        sys.exit(1)


def get_interface_ip(interface_name: str = None) -> str:
    """Get the IPv4 address of a network interface."""
    try:
        if interface_name:
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        else:
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                iface = default_gateway[1]
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _init_established_session(s: socket.socket, client_key, send_ip: str, listen_port: int,
                              pkt_seq: int, pkt_ack: int, win: int,
                              expected_ack: int, initial_payload: bytes) -> conn_struct:
    """Create ESTABLISHED conn_struct and TCP control state, handling any piggybacked payload."""
    client_ip, client_port = client_key
    receiver = ReceiveReorderBuffer(initial_seq=pkt_seq, capacity=RECEIVE_CAPACITY)
    sender = ReliableSendBuffer(initial_seq=pkt_ack)
    flow = FlowControlWindow(rwnd=win)
    congestion = CubicController(mss=TCP_MSS)
    rtt = RttEstimator()

    initial_ready = b""
    if initial_payload:
        initial_ready = receiver.receive(pkt_seq, initial_payload)
        ack_pkt = build_tcp_packet(
            send_ip, client_ip, listen_port, client_port,
            seq=pkt_ack, ack_seq=receiver.rcv_nxt, ack=1,
            window=max(0, receiver.capacity - receiver.buffered_bytes - len(initial_ready))
        )
        ip_hdr = build_ip_header(send_ip, client_ip, socket.IPPROTO_TCP, len(ack_pkt))
        s.sendto(ip_hdr + ack_pkt, (client_ip, 0))

    session = conn_struct(
        client_ip=client_ip,
        client_port=client_port,
        server_ip=send_ip,
        server_port=listen_port,
        state="ESTABLISHED",
        server_seq=pkt_ack,
        client_seq=receiver.rcv_nxt,
        expected_final_ack=expected_ack,
        last_activity=time.time()
    )
    with connections_lock:
        connections[client_key] = session
        _conn_states[client_key] = {
            "lock": threading.RLock(),
            "sender": sender,
            "receiver": receiver,
            "rtt": rtt,
            "flow": flow,
            "congestion": congestion,
            # Bytes already made contiguous during the handshake remain unread by the app.
            "unread": bytearray(initial_ready),
        }
    return session


def accept(s: socket.socket, listen_ip: str, listen_port: int, interface_name: str = None) -> conn_struct:
    """Accept a new connection by performing the 3-way handshake using raw sockets."""
    start_packet_dispatcher(s, listen_port)
    _ensure_cleanup_thread()

    if listen_ip == "0.0.0.0":
        send_ip = get_interface_ip(interface_name)
        print(f"[Streap_raw] accept: listen_ip=0.0.0.0, using send_ip={send_ip} for outgoing packets")
    else:
        send_ip = listen_ip

    print(f"[Streap_raw] accept: Waiting for incoming connections on {listen_ip}:{listen_port} (send_ip={send_ip})...")
    try:
        while True:
            syn_q = get_packet_queue(_SYN_KEY)
            try:
                packet, _addr = syn_q.get(timeout=1.0)
            except queue.Empty:
                continue

            decoded = _decode_packet(packet)
            if decoded is None:
                continue
            src_port, dest_port, pkt_seq, pkt_ack, flags, win, initial_payload = decoded
            if dest_port != listen_port:
                continue

            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4
            client_ip = socket.inet_ntoa(packet[12:16])
            client_port = src_port
            client_key = (client_ip, client_port)

            # STEP 1: Obtain client SYN
            if syn_flag == 1 and ack_flag == 0:
                with handshake_lock:
                    if handshake_in_progress.get(client_key, False):
                        continue
                    handshake_in_progress[client_key] = True

                q = get_packet_queue(client_key)
                server_seq = _generate_isn()
                next_ack = seq_add(pkt_seq, 1)
                expected_ack = seq_add(server_seq, 1)

                # STEP 2: Send SYN-ACK
                syn_ack_packet = build_tcp_packet(
                    send_ip, client_ip, listen_port, client_port,
                    seq=server_seq, ack_seq=next_ack, syn=1, ack=1,
                    window=RECEIVE_CAPACITY
                )
                ip_header = build_ip_header(send_ip, client_ip, socket.IPPROTO_TCP, len(syn_ack_packet))
                s.sendto(ip_header + syn_ack_packet, (client_ip, 0))

                with connections_lock:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="SYN_RCVD",
                        server_seq=server_seq,
                        client_seq=pkt_seq,
                        expected_final_ack=expected_ack,
                        last_activity=time.time()
                    )

                # STEP 3: Wait for client's final ACK (and capture any piggybacked payload)
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    try:
                        pkt3, _ = q.get(timeout=0.5)
                    except queue.Empty:
                        continue

                    dec3 = _decode_packet(pkt3)
                    if dec3 is None:
                        continue
                    _, _, seq3, ack3, flags3, win3, payload3 = dec3
                    syn3 = (flags3 & 0x02) >> 1
                    ack3_flag = (flags3 & 0x10) >> 4

                    if syn3 == 0 and ack3_flag == 1:
                        with connections_lock:
                            cur = connections.get(client_key)
                            if cur is None or cur.state != "SYN_RCVD":
                                break
                        if not _valid_final_ack(seq3, cur.client_seq, ack3, expected_ack):
                            continue
                        session = _init_established_session(
                            s, client_key, send_ip, listen_port,
                            seq3, ack3, win3, expected_ack, payload3
                        )
                        with handshake_lock:
                            handshake_in_progress.pop(client_key, None)
                        print(f"[Streap_raw] Handshake established with ({client_ip}:{client_port})")
                        return session

                with handshake_lock:
                    handshake_in_progress.pop(client_key, None)
                _remove_connection(client_key)
                continue

            # STEP 3 Fallback: Final ACK arrived on SYN queue
            with connections_lock:
                existing = connections.get(client_key)
            if (existing is not None and existing.state == "SYN_RCVD"
                    and syn_flag == 0 and ack_flag == 1
                    and _valid_final_ack(pkt_seq, existing.client_seq,
                                         pkt_ack, existing.expected_final_ack)):
                session = _init_established_session(
                    s, client_key, send_ip, listen_port,
                    pkt_seq, pkt_ack, win, existing.expected_final_ack, initial_payload
                )
                with handshake_lock:
                    handshake_in_progress.pop(client_key, None)
                print(f"[Streap_raw] Handshake established (fallback) with ({client_ip}:{client_port})")
                return session

    except KeyboardInterrupt:
        print("\n[-] Server stopped.")
        with handshake_lock:
            handshake_in_progress.clear()
        raise


def _send_ack_only(s: socket.socket, server_ip: str, client_ip: str,
                   server_port: int, client_port: int,
                   seq: int, ack_seq: int, window: int):
    tcp = build_tcp_packet(
        server_ip, client_ip, server_port, client_port,
        seq=seq, ack_seq=ack_seq, ack=1, window=window
    )
    ip = build_ip_header(server_ip, client_ip, socket.IPPROTO_TCP, len(tcp))
    s.sendto(ip + tcp, (client_ip, 0))


def run_conn_recv(s: socket.socket, conn_info: conn_struct) -> bytes:
    """Receive contiguous ordered bytes on an established connection."""
    client_key = (conn_info.client_ip, conn_info.client_port)
    with connections_lock:
        session = connections.get(client_key)
        st = _conn_states.get(client_key)
    if session is None or st is None:
        return b""

    _touch_connection(client_key)

    # Return bytes buffered during handshake or while run_conn_send() was active.
    already_ready = _take_unread(st)
    if already_ready:
        # Reading from the app buffer frees receive capacity; advertise the update
        # so a peer previously blocked by a zero/small window can resume sending.
        with st["lock"]:
            snd_nxt = st["sender"].snd_nxt
            rcv_nxt = st["receiver"].rcv_nxt
            adv_win = _advertised_window(st)
        _send_ack_only(
            s, session.server_ip, session.client_ip,
            session.server_port, session.client_port,
            seq=snd_nxt, ack_seq=rcv_nxt, window=adv_win
        )
        return already_ready

    if session.state in ("CLOSE_WAIT", "CLOSED"):
        return b""

    q = get_packet_queue(client_key)
    while True:
        with connections_lock:
            session = connections.get(client_key)
            st = _conn_states.get(client_key)
        if session is None or st is None or session.state in ("CLOSE_WAIT", "CLOSED"):
            return b""

        try:
            packet, _ = q.get(timeout=1.0)
        except queue.Empty:
            continue

        decoded = _decode_packet(packet)
        if decoded is None:
            continue

        _touch_connection(client_key)
        _src, _dst, seq, ack, flags, window, payload = decoded
        ack_flag = bool(flags & 0x10)
        syn_flag = bool(flags & 0x02)
        fin_flag = bool(flags & 0x01)
        rst_flag = bool(flags & 0x04)

        if rst_flag:
            _remove_connection(client_key)
            return b""

        with st["lock"]:
            st["flow"].update(window)
            if ack_flag:
                acked, samples = st["sender"].acknowledge(ack, window=window)
                if acked > 0:
                    for sample in samples:
                        st["rtt"].sample(sample)
                    st["congestion"].on_ack(acked_bytes=acked)

            ready = b""
            if payload and not syn_flag:
                _receive_payload(st, seq, payload)
                ready = bytes(st["unread"])
                st["unread"].clear()

            rcv_nxt = st["receiver"].rcv_nxt
            snd_nxt = st["sender"].snd_nxt
            adv_win = _advertised_window(st)

            peer_closed = False
            if fin_flag and seq_add(seq, len(payload)) == rcv_nxt:
                rcv_nxt = seq_add(rcv_nxt, 1)
                st["receiver"].rcv_nxt = rcv_nxt
                peer_closed = True

        with connections_lock:
            if client_key in connections:
                new_state = "CLOSE_WAIT" if peer_closed else connections[client_key].state
                connections[client_key] = connections[client_key]._replace(
                    state=new_state,
                    server_seq=snd_nxt,
                    client_seq=rcv_nxt,
                    last_activity=time.time()
                )

        if (payload and not syn_flag) or peer_closed:
            _send_ack_only(
                s, session.server_ip, session.client_ip,
                session.server_port, session.client_port,
                seq=snd_nxt, ack_seq=rcv_nxt, window=adv_win
            )

        if ready:
            return ready
        if peer_closed:
            return b""


def run_conn_send(s: socket.socket, conn_info: conn_struct, payload: bytes) -> int:
    """Transmit reliably using rwnd/cwnd, RTT/RTO, retransmission and Fast Retransmit.

    Retries are bounded per segment (eight retransmissions); this is not a
    strict wall-clock deadline because the RTO backs off exponentially.
    """
    if not payload:
        return 0

    client_key = (conn_info.client_ip, conn_info.client_port)
    with connections_lock:
        session = connections.get(client_key)
        st = _conn_states.get(client_key)
    if session is None or st is None:
        print(f"[Streap_raw] run_conn_send: connection not found for {client_key}")
        return -1

    _touch_connection(client_key)
    q = get_packet_queue(client_key)
    data_mv = memoryview(payload)
    offset = 0
    total_len = len(data_mv)

    try:
        while offset < total_len or st["sender"].bytes_in_flight > 0:
            with connections_lock:
                session = connections.get(client_key)
            if session is None:
                return -1

            # 1. Transmit as many segments as allowed by min(rwnd, cwnd)
            while offset < total_len:
                with st["lock"]:
                    budget = st["flow"].send_budget(
                        st["sender"].bytes_in_flight,
                        st["congestion"].cwnd
                    )
                    if budget <= 0:
                        # Zero-Window Probing (RFC 9293): send 1 byte when rwnd == 0
                        # and nothing is in flight so a lost window-update ACK cannot deadlock.
                        if st["flow"].rwnd == 0 and st["sender"].bytes_in_flight == 0:
                            amount = 1
                        else:
                            break
                    else:
                        amount = min(TCP_MSS, budget, total_len - offset)

                    chunk = bytes(data_mv[offset:offset + amount])
                    offset += amount
                    seg = st["sender"].add(chunk)
                    ack_seq = st["receiver"].rcv_nxt
                    adv_win = _advertised_window(st)

                send_tcp_data_segment(
                    s, session.server_ip, session.client_ip,
                    session.server_port, session.client_port,
                    seg.seq, ack_seq, seg.data, window=adv_win
                )
                _touch_connection(client_key)

            # 2. Wait for ACKs or RTO expiry
            with st["lock"]:
                if st["sender"].bytes_in_flight == 0 and offset >= total_len:
                    break
                timer_start = st["sender"]._timer_started_at
                rto = st["rtt"].rto
            wait_timeout = max(0.01, rto - (time.monotonic() - timer_start)) if timer_start is not None else 0.05

            try:
                packet, _ = q.get(timeout=wait_timeout)
            except queue.Empty:
                # RTO expired -> retransmit oldest unacknowledged segment
                with st["lock"]:
                    due = st["sender"].due_for_retransmission(st["rtt"].rto)
                    if not due:
                        continue
                    if any(seg.transmissions > 8 for seg in due):
                        print(f"[Streap_raw] Max retransmissions exceeded for {client_key}")
                        return -1
                    st["rtt"].backoff()
                    # Do not shrink cwnd when retransmitting a 1-byte Zero-Window Probe
                    if st["flow"].rwnd > 0:
                        st["congestion"].on_loss()
                    retrans_seg = due[0]
                    ack_seq = st["receiver"].rcv_nxt
                    adv_win = _advertised_window(st)

                send_tcp_data_segment(
                    s, session.server_ip, session.client_ip,
                    session.server_port, session.client_port,
                    retrans_seg.seq, ack_seq, retrans_seg.data, window=adv_win
                )
                _touch_connection(client_key)
                continue

            decoded = _decode_packet(packet)
            if decoded is None:
                continue

            _touch_connection(client_key)
            _src, _dst, seq, ack, flags, window, in_payload = decoded
            ack_flag = bool(flags & 0x10)
            syn_flag = bool(flags & 0x02)
            fin_flag = bool(flags & 0x01)
            rst_flag = bool(flags & 0x04)

            if rst_flag:
                _remove_connection(client_key)
                return -1

            fast_retrans_seg = None
            need_ack_reply = False

            with st["lock"]:
                st["flow"].update(window)

                if ack_flag:
                    acked, samples = st["sender"].acknowledge(ack, window=window)
                    if acked > 0:
                        for sample in samples:
                            st["rtt"].sample(sample)
                        st["congestion"].on_ack(acked_bytes=acked)
                    else:
                        dup_seg = st["sender"].on_duplicate_ack(
                            ack, window,
                            has_payload=bool(in_payload),
                            syn_or_fin=(syn_flag or fin_flag),
                        )
                        if dup_seg is not None:
                            if st["flow"].rwnd > 0:
                                st["congestion"].on_loss()
                            fast_retrans_seg = dup_seg

                # Handle any incoming data or FIN arriving while we are sending
                if in_payload and not syn_flag:
                    _receive_payload(st, seq, in_payload)
                    need_ack_reply = True

                rcv_nxt = st["receiver"].rcv_nxt
                snd_nxt = st["sender"].snd_nxt
                adv_win = _advertised_window(st)
                peer_closed = False
                if fin_flag and seq_add(seq, len(in_payload)) == rcv_nxt:
                    rcv_nxt = seq_add(rcv_nxt, 1)
                    st["receiver"].rcv_nxt = rcv_nxt
                    peer_closed = True
                    need_ack_reply = True

            with connections_lock:
                if client_key in connections:
                    new_state = "CLOSE_WAIT" if peer_closed else connections[client_key].state
                    connections[client_key] = connections[client_key]._replace(
                        state=new_state,
                        server_seq=snd_nxt,
                        client_seq=rcv_nxt,
                        last_activity=time.time()
                    )

            if fast_retrans_seg is not None:
                send_tcp_data_segment(
                    s, session.server_ip, session.client_ip,
                    session.server_port, session.client_port,
                    fast_retrans_seg.seq, rcv_nxt, fast_retrans_seg.data, window=adv_win
                )

            if need_ack_reply:
                _send_ack_only(
                    s, session.server_ip, session.client_ip,
                    session.server_port, session.client_port,
                    seq=snd_nxt, ack_seq=rcv_nxt, window=adv_win
                )

        return total_len
    except Exception as e:
        print(f"[Streap_raw] run_conn_send error for {client_key}: {e}")
        return -1


def close_connection(s: socket.socket, conn_info: conn_struct):
    """Gracefully close a TCP connection using FIN handshake and clean up state."""
    client_key = (conn_info.client_ip, conn_info.client_port)
    with connections_lock:
        session = connections.get(client_key)
        st = _conn_states.get(client_key)
    if session is None:
        _remove_connection(client_key)
        return

    if st is not None:
        with st["lock"]:
            fin_seq = st["sender"].snd_nxt
            ack_seq = st["receiver"].rcv_nxt
            adv_win = _advertised_window(st)
    else:
        fin_seq = session.server_seq
        ack_seq = session.client_seq
        adv_win = RECEIVE_CAPACITY

    def _send_fin():
        fin_pkt = build_tcp_packet(
            session.server_ip, session.client_ip,
            session.server_port, session.client_port,
            seq=fin_seq, ack_seq=ack_seq, ack=1, fin=1, window=adv_win
        )
        ip_hdr = build_ip_header(session.server_ip, session.client_ip, socket.IPPROTO_TCP, len(fin_pkt))
        s.sendto(ip_hdr + fin_pkt, (session.client_ip, 0))

    _send_fin()
    expected_fin_ack = seq_add(fin_seq, 1)
    fin_acked = False
    peer_fin = (session.state == "CLOSE_WAIT")
    q = get_packet_queue(client_key)
    deadline = time.time() + 2.0

    while not (fin_acked and peer_fin) and time.time() < deadline:
        try:
            packet, _ = q.get(timeout=0.4)
        except queue.Empty:
            if not fin_acked:
                _send_fin()
            continue

        decoded = _decode_packet(packet)
        if decoded is None:
            continue
        _src, _dst, pkt_seq, pkt_ack, flags, _win, payload = decoded
        if flags & 0x04:  # RST
            break
        if (flags & 0x10) and seq_le(expected_fin_ack, pkt_ack):
            fin_acked = True
        if flags & 0x01:  # FIN
            peer_fin = True
            peer_fin_ack_seq = seq_add(seq_add(pkt_seq, len(payload)), 1)
            _send_ack_only(
                s, session.server_ip, session.client_ip,
                session.server_port, session.client_port,
                seq=expected_fin_ack, ack_seq=peer_fin_ack_seq, window=adv_win
            )

    _remove_connection(client_key)
    print(f"[Streap_raw] Closed and cleaned up connection {client_key}")


def close_all_connections():
    """Close all connections and clean up."""
    with connections_lock:
        keys = list(connections.keys())
    for k in keys:
        _remove_connection(k)