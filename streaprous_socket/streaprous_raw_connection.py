#
# Copyright (C) 2026 pdnguyen of HCMC University of Technology VNU-HCM.
# All rights reserved.
# This file is part of the CO3093/CO3094 course,
# and is released under the LICENSE. Please see the LICENSE
# file that should have been included as part of this package.
#
# StreapRous release
#
# The authors hereby grant to Licensee personal permission to use
# and modify the Licensed Source Code for the sole purpose of studying
# while attending the course
#

"""
StreapRous Raw Connection Library
A library for handling TCP connections with raw sockets.
Based on raw_connection_server.py implementation.
Provides connection management, send/receive functionality using raw sockets.
"""

import socket
import struct
import sys
import threading
import time
import queue
from collections import namedtuple
import netifaces

# Import streaprout packet dispatcher functions
from .streaprous_packet_dispatcher import (
    start_packet_dispatcher,
    stop_packet_dispatcher,
    get_packet_queue,
    remove_packet_queue,
    _packet_dispatcher_lock,
    _SYN_KEY,
)

# Connection structure 
# This structure holds connection and its state information
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



# Global table to manage multiple connection
# The mapping include {key: value} as { (client_ip, client_port): conn_struct }
connections = {}
connections_lock = threading.Lock()

# Management structure to serialize the 3-way handshake
# Each hand shake is manage by a unique ID client_key
# including client_ip client_port
handshake_lock = threading.Lock()
handshake_in_progress = {}


# Default raw port listener
DEFAULT_LISTEN_IP = "0.0.0.0"
DEFAULT_LISTEN_PORT = 22239
DEFAULT_INTERFACE_NAME = "lo0"

def register_keep_port_alive(listen_ip="0.0.0.0", listen_port=22239, retry_interval=10):
    """
    Periodically register and maintain TCP port.
    Retry registration whenever binding/listening fails.
    Never accept incoming connections.
    
    Args:
        listen_ip: IP address to bind to (default: "0.0.0.0")
        listen_port: Port to bind to (default: 22239)
        retry_interval: Seconds to wait before retrying after failure (default: 10)
    
    Returns:
        threading.Thread: The background thread running the port keep-alive
    """
    def _keep_alive():
        print(f"[Streap_raw]  Start port keep-alive thread for {listen_ip}:{listen_port}")
        attempt = 0
        while True:
            attempt += 1
            standard_sock = None

            try:
                print(f"[Streap_raw] register_keep_port_alive: Attempt #{attempt} - Create socket...")
                standard_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                standard_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                print(f"[Streap_raw] register_keep_port_alive: Bind to {listen_ip}:{listen_port}...")
                standard_sock.bind((listen_ip, listen_port))
                
                print(f"[Streap_raw] register_keep_port_alive: Listen on port {listen_port}...")
                standard_sock.listen(0)  # No backlog, we won't accept connections
                print(f"[Streap_raw] register_keep_port_alive: Done port {listen_port} registration.")

                # Keep socket alive until an error occurs.
                while True:
                    time.sleep(3600)
            except Exception as e:
                print(f"[Streap_raw] register_keep_port_alive: Fail port registration with error {e}")
            finally:
                if standard_sock:
                    print(f"[Streap_raw] register_keep_port_alive: Close socket...")
                    standard_sock.close()

            print(f"[Streap_raw] register_keep_port_alive: Retry port registration in {retry_interval}s... (attempt #{attempt + 1})")
            time.sleep(retry_interval)
    
    print(f"[Streap_raw] register_keep_port_alive: Starting background thread for port {listen_port}")
    thread = threading.Thread(target=_keep_alive, daemon=True, name=f"port-keep-alive-{listen_port}")
    thread.start()
    print(f"[Streap_raw] register_keep_port_alive: Thread started (name={thread.name})")
    return thread


def checksum(msg):
    """Calculates a checksum and returns computed values.

    Args:
         msg message data
    """
    if len(msg) % 2 == 1:
        msg += b'\x00'
    s = 0
    for i in range(0, len(msg), 2):
        w = struct.unpack('!H', msg[i:i+2])[0]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

from .streaprous_flow_control import RCV_BUF, flow, current_rwnd, need_window_update

def build_tcp_packet(src_ip, dest_ip, src_port, dst_port, seq, ack_seq, syn=0, ack=0, fin=0, rcv_wnd=RCV_BUF):
    """Stitches a structurally flawless 20-byte TCP header.

    Args:
         src_ip    Source IP address
         dest_ip   Destination IP address
         src_port  Source port
         dst_port  Destination port
         seq       Sequence number
         ack_seq   ACK for sequence
         syn=0     SYN flag
         ack=0     ACK flag
         fin=0     FIN flag
    """
    flags = (ack << 4) + (syn << 1) + fin
    offset_res = (5 << 4) + 0  # 20 bytes data offset (5 * 4)
    window = rcv_wnd
    urg_ptr = 0
    draft_checksum = 0

    # Build a draft (20 byte) header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    # Build addressing-header
    address_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_temp)
    )
    
    # Calculate mathematical checksum integer
    tcp_checksum = checksum(address_header+ tcp_header_temp)
    
    # Build the final TCP packet
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )
    
    return tcp_header


def build_ip_header(src_ip, dest_ip, protocol, payload_len):
    """Builds a structurally flawless 20-byte IP header.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         protocol     Protocol number
         payload_len  Payload length
    """
    version_ihl = (4 << 4) | 5  # Version 4, IHL 5 (20 bytes)
    tos = 0
    total_len = 20 + payload_len  # IP header + payload

    # TODO: We draft with no-fragment package
    #       Full implementation must include fragment
    #       handling function
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


def send_tcp_data_segment(s, src_ip, dest_ip, src_port, dst_port, seq, ack_seq, payload, rwnd=RCV_BUF):
    """Assembles and transmits a single TCP segment containing data payload.

    Args:
         src_ip       Source IP address
         dest_ip      Destination IP address
         src_port     Source port
         dst_port     Destination port
         seq          Sequence number
         ack_seq      ACK for sequence
         syn          SYN flag
         ack          ACK flag
         payload      Payload

    """

    # TODO: Hardcode for fast data pushing
    #       The setting PSH + ACK
    #       need to modify in full schema
    flags = 0x18
    offset_res = (5 << 4) + 0
    window = rwnd
    urg_ptr = 0
    draft_checksum = 0
    
    # Build draft header with no checksum
    tcp_header_temp = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, draft_checksum, urg_ptr
    )
    
    tcp_len = len(tcp_header_temp) + len(payload)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, tcp_len
    )

    # Calculate the checksum    
    tcp_checksum = checksum(pseudo + tcp_header_temp + payload)

    # Build the full TCP packet header    
    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dst_port, seq, ack_seq,
        offset_res, flags, window, tcp_checksum, urg_ptr
    )

    # Build the full IP packet header     
    ip_header = build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload))

    # Build the full packet header     
    full_packet = ip_header + tcp_header + payload

    # Send packet
    print(f"[Streap_raw] send_tcp_data_segment: seq={seq}, ack_seq={ack_seq}, payload_len={len(payload)}, flags=0x{flags:02x}")
    print(f"[Streap_raw] send_tcp_data_segment: TCP header seq={seq}, ack_seq={ack_seq}, flags=0x{flags:02x}")
    s.sendto(full_packet, (dest_ip, 0))
    
    return len(payload)


def clean_expired_connections(timeout=60):
    """Background thread to clean up stale or timed-out connections.

    Args:
         timeout Time expiration for clean-up working
    """
    while True:
        time.sleep(10)
        now = time.time()
        with connections_lock:
            expired = [k for k, session in connections.items() if now - session.last_activity > timeout]
        for k in expired:
            print(f"[Streap_raw] clean_expired_connections: Session [{k[0]}:{k[1]}] Connection timed out ({timeout}s inactivity). Remove connection.")
            forget_connection(k)


def create_raw_socket() -> socket.socket:
    """
    Create a raw socket for TCP protocol. The raw socket requires root privileges.
    It is raw with listen all packet for incoming port.
    
    Returns:
        Raw socket object
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # TODO: port listener need to be post-procesed later
        #       raw_socket ignore the transport protocol deatails

        print(f"[Streap_raw] Create raw socket binding for 0.0.0.0 listening")
        return sock
    except PermissionError:
        print("Error: Root privileges required (sudo).")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating raw socket: {e}")
        sys.exit(1)


def get_interface_ip(interface_name: str = None) -> str:
    """
    Get the IPv4 address of a network interface.
    
    Args:
        interface_name: Network interface name (e.g., 'enp0s8', 'eth0', 'en0')
                        If None, tries to find the default route interface.
    
    Returns:
        IPv4 address string
    """
    try:
        if interface_name:
            addrs = netifaces.ifaddresses(interface_name)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0]['addr']
        else:
            # Try to get default route interface
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {}).get(netifaces.AF_INET)
            if default_gateway:
                iface = default_gateway[1]
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    return addrs[netifaces.AF_INET][0]['addr']
    except Exception:
        pass
    
    # Fallback: try to get any non-loopback IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def accept(s: socket.socket, listen_ip: str, listen_port: int, interface_name: str = None) -> conn_struct:
    """
    Accept a new connection by performing the 3-way handshake using raw sockets.
    Returns a conn_struct tuple for the established connection.
    Handshakes are serialized to ensure only one 3-way handshake is processed at a time.
    
    Args:
        s: Raw socket
        listen_ip: Server IP to listen on (e.g., '0.0.0.0')
        listen_port: Server port to listen on
        interface_name: Network interface name for sending packets (optional)
    
    Returns:
        conn_struct: Established connection information
    """
    # Start packet dispatcher for this port
    start_packet_dispatcher(s, listen_port)
    
    # Get actual source IP for sending packets
    if listen_ip == "0.0.0.0":
        send_ip = get_interface_ip(interface_name)
        print(f"[Streap_raw] accept: listen_ip=0.0.0.0, using send_ip={send_ip} for outgoing packets")
    else:
        send_ip = listen_ip
    
    server_seq = 2000
    client_ip = None
    client_port = None

    print(f"[Streap_raw] accept: Waiting for incoming connections on {listen_ip}:{listen_port} (send_ip={send_ip})...")
    try:
        while True:
            # Get packet from dispatcher queue (for SYN packets)
            syn_q = get_packet_queue(_SYN_KEY)
            try:
                packet, addr = syn_q.get(timeout=1.0)
                print(f"[Streap_raw] accept: Got packet from SYN queue")
            except queue.Empty:
                continue

            # Extract IP Header Length
            ihl = (packet[0] & 0x0F) * 4
            tcp_packet = packet[ihl:]
            
            if len(tcp_packet) < 20:
                continue

            # Unpack the received TCP header
            tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
            src_port, dest_port, pkt_seq, pkt_ack, flags = (
                tcph[0],
                tcph[1],
                tcph[2],
                tcph[3],
                tcph[5],
            )

            # Bypass non-listen port
            if dest_port != listen_port:
                continue

            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4

            # Build client_key from client IP and client port
            client_ip = socket.inet_ntoa(packet[12:16])
            client_port = src_port
            client_key = (client_ip, client_port)
            print(f"\n[Streap_raw] accept: Receive packet from Client ({client_ip}:{client_port}) (Seq={pkt_seq}, SYN={syn_flag}, ACK={ack_flag})")

            # Create queue for each connection associated 
            # with tupple client_key=(client_ip, client_port)
            q = get_packet_queue(client_key)
            print(f"[Streap_raw] accept: Created per-connection queue for {client_key}")
            with connections_lock:
                # Declare initialized session if not available
                if client_key not in connections:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="LISTEN",
                        server_seq=2000,
                        client_seq=0,
                        expected_final_ack=0,
                        last_activity=time.time(),                      
                    )
                session = connections[client_key]

                        
            # Perform 3 handshake step
            # STEP 1: Obtain client SYN 
            if syn_flag == 1 and ack_flag == 0:
                print(f"\nHandshake1: Received SYN from Client ({client_ip}:{client_port}) (Seq={pkt_seq})")

                # Quick duplicate handshake check (fast, no heavy operations)
                with handshake_lock:
                    if handshake_in_progress.get(client_key, False):
                        print(f"[Streap_raw] accept: Handshake already in progress for {client_ip}:{client_port}, dropping SYN")
                        continue
                    handshake_in_progress[client_key] = True

                # STEP 2: Reply SYN-ACK immediately
                # Build TCP packet for SYN-ACK
                next_ack = pkt_seq + 1
                syn_ack_packet = build_tcp_packet(send_ip, client_ip, listen_port, client_port,
                                                  seq=server_seq, ack_seq=next_ack, syn=1, ack=1)
                ip_header = build_ip_header(send_ip, client_ip, socket.IPPROTO_TCP, len(syn_ack_packet))
                full_packet = ip_header + syn_ack_packet

                # Send SYN-ACK packet
                print(f"[Streap_raw] accept: Sending SYN-ACK to {client_ip}:{client_port} from {send_ip}:{listen_port}")
                print(f"[Streap_raw] accept: SYN-ACK packet size: {len(full_packet)} bytes (IP={len(ip_header)}, TCP={len(syn_ack_packet)})")
                bytes_sent = s.sendto(full_packet, (client_ip, 0))
                print(f"Handshake2: Sent SYN-ACK to Client (Seq={server_seq}, Ack={next_ack}, bytes_sent={bytes_sent})")

                # Register connection to the associated queue for each connection associated 
                # with tupple client_key=(client_ip, client_port)
                with connections_lock:
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,  # Use actual sending IP
                        server_port=listen_port,
                        state="SYN_RCVD",
                        server_seq=server_seq,
                        client_seq=pkt_seq,
                        expected_final_ack=server_seq + 1,
                        last_activity=time.time()
                    )
                    session = connections[client_key]

                # STEP 3: Wait for client FIN-ACK
                # The final ACK will arrive on the per-connection queue, not the SYN queue
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    try:
                        packet, addr = q.get(timeout=0.5)
                        print(f"[Streap_raw] accept: Got packet from per-connection queue for {client_ip}:{client_port}")
                    except queue.Empty:
                        print(f"[Streap_raw] accept: Per-connection queue empty for {client_ip}:{client_port}, waiting...")
                        continue

                    # Extract IP Header Length
                    ihl = (packet[0] & 0x0F) * 4
                    tcp_packet = packet[ihl:]
                    
                    if len(tcp_packet) < 20:
                        continue

                    # Unpack the received TCP header
                    tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
                    src_port, dest_port, pkt_seq, pkt_ack, flags = (
                        tcph[0],
                        tcph[1],
                        tcph[2],
                        tcph[3],
                        tcph[5],
                    )

                    syn_flag = (flags & 0x02) >> 1
                    ack_flag = (flags & 0x10) >> 4
                    print(f"[Streap_raw] accept: Received packet in handshake wait - SYN={syn_flag}, ACK={ack_flag}, Seq={pkt_seq}, Ack={pkt_ack}")

                    # Check if this is the final ACK (ACK only, no SYN)
                    if syn_flag == 0 and ack_flag == 1:
                        print(f"[Streap_raw] accept: handshake3 Received FIN-ACK from Client (Seq={pkt_seq}, Ack={pkt_ack})")

                        with connections_lock:
                            if session.state != "SYN_RCVD":
                                print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                                break

                            # Update connection to ESTABLISHED
                            connections[client_key] = conn_struct(
                                client_ip=client_ip,
                                client_port=client_port,
                                server_ip=send_ip,
                                server_port=listen_port,
                                state="ESTABLISHED",
                                server_seq=pkt_ack,
                                client_seq=pkt_seq,
                                expected_final_ack=session.expected_final_ack,
                                last_activity=time.time()
                            )
                            
                            flow[client_key] = {
                                "peer_rwnd": tcph[6],
                                "rcv_buffer": bytearray(),
                                "next_to_read": pkt_seq,
                                "unanswered_probes": 0,
                                "last_probe": 0.0,
                            }
                                                        
                            session = connections[client_key]


                        # Clear handshake in progress flag
                        with handshake_lock:
                            handshake_in_progress[client_key] = False

                        print(f"[Streap_raw] Established handshake with connection: ({client_ip}:{client_port}) ESTABLISHED")
                        
                        # Return the established connection info
                        return session
                
                # Fallback of the handshake timeout
                print(f"[Streap_raw] Handshake timeout for {client_ip}:{client_port}")
                with handshake_lock:
                    handshake_in_progress[client_key] = False
                remove_packet_queue(client_key)
                forget_connection(client_key)
                continue


            # STEP 3 Exception handling: Capture FIN ACK on SYN queue ---
            if session.state == "SYN_RCVD" and syn_flag == 0 and ack_flag == 1:
                print(f"[Streap_raw] accept: handshake3 received Final ACK from Client on SYN queue (Seq={pkt_seq}, Ack={pkt_ack})")
                print(f"[Streap_raw] accept: Fallback - got final ACK on SYN queue for {client_ip}:{client_port}")

                with connections_lock:
                    if session.state != "SYN_RCVD":
                        print(f"[Streap_raw] accept: Non handshake state for {client_ip}:{client_port}")
                        continue

                    # Update connection to ESTABLISHED
                    connections[client_key] = conn_struct(
                        client_ip=client_ip,
                        client_port=client_port,
                        server_ip=send_ip,
                        server_port=listen_port,
                        state="ESTABLISHED",
                        server_seq=pkt_ack,
                        client_seq=pkt_seq,
                        expected_final_ack=session.expected_final_ack,
                        last_activity=time.time()
                    )
                    session = connections[client_key]
                    flow[client_key] = {
                        "peer_rwnd": tcph[6],
                        "rcv_buffer": bytearray(),
                        "next_to_read": pkt_seq,
                        "unanswered_probes": 0,
                        "last_probe": 0.0,
                    }

                # Clear handshake in progress flag
                with handshake_lock:
                    handshake_in_progress[client_key] = False

                print(f"[Streap_raw] Etablished handshak with connection: ({client_ip}:{client_port}) ESTABLISHED")
                
                # Return the established connection info
                return session

    except KeyboardInterrupt:
        print("\n[-] Server stopped.")
        # Clear handshake flags on interrupt
        with handshake_lock:
            handshake_in_progress.clear()
        raise


def run_conn_recv(sock: socket.socket, conn_info: conn_struct, max_bytes=4096) -> bytes:
    """Wrapper utilizing teammate's reliable_receive for raw TCP sockets."""
    # Imported here, not at the top: streaprous_reliability imports this module,
    # so a top-level import is circular.
    
    
    from .streaprous_reliability import reliable_receive
    key = (conn_info.client_ip, conn_info.client_port)                   
    with connections_lock:
        session = connections.get(key)
    if session is None or key not in flow:
        return b""
    st = flow[key]
    
    """The legacy function hand data directly to the app, the newer approach store them in rcv_buffer for the app to read"""
    
    #Handle client's FIN
    if session.state == "CLOSE_WAIT":
        data = bytes(st["rcv_buffer"][:max_bytes])
        del st["rcv_buffer"][:max_bytes]
        st["next_to_read"] += len(data)
        return data
    closed = reliable_receive(sock, conn_info)
    with connections_lock:  
        session = connections.get(key)
    if session is None:
        return b""
    old = current_rwnd(key, session.client_seq)

    data = bytes(st["rcv_buffer"][:max_bytes])
    del st["rcv_buffer"][:max_bytes]
    st["next_to_read"] += len(data)

    new = current_rwnd(key, session.client_seq)
    #Send a window update if needed
    if need_window_update(old, new):
        header = build_ip_header(session.server_ip, session.client_ip, socket.IPPROTO_TCP, 20)
        ack = build_tcp_packet(session.server_ip, session.client_ip, session.server_port, session.client_port,
                               seq=session.server_seq, ack_seq=session.client_seq, ack=1, rcv_wnd=new)
        sock.sendto(header + ack, (session.client_ip, 0))
        print(f"[Streap_flctrl] window update {old} -> {new}")
    return data

def run_conn_send(sock: socket.socket, conn_info: conn_struct, payload: bytes) -> int:
    """Wrapper utilizing teammate's reliable_send for raw TCP sockets."""
    key = (conn_info.client_ip, conn_info.client_port)
    with connections_lock:
        session = connections.get(key)
    if session is None:
        return 0, None
    from .streaprous_reliability import reliable_send
    sent, next_seq = reliable_send(
        sock, conn_info.server_ip, conn_info.client_ip,
        conn_info.server_port, conn_info.client_port,
        seq=session.server_seq, ack_seq=session.client_seq,
        payload=payload,
        rcv_wnd = current_rwnd(key, session.client_seq)
    )
    
    with connections_lock:
        if key in connections:
            connections[key] = connections[key]._replace(server_seq=next_seq)
    return sent, next_seq



def close_connection(s: socket.socket, conn_info: conn_struct):
    """Close a specific connection by sending FIN and removing from connection table."""

    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
        
    #Connection teardown
        
    def send_FIN():
        
        fin_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                          seq=session.server_seq, ack_seq=session.client_seq, ack=1, fin=1)
        ip_header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, len(fin_packet))
        s.sendto(ip_header + fin_packet, (client_ip, 0))
        
    with connections_lock:
        if client_key in connections:
            session = connections[client_key]
            # Send FIN packet
            send_FIN()
            print(f"[Streap_raw] run_conn_send: Send FIN to {client_ip}:{client_port}")
        else:
            return

    fin_acked = False
    peer_fin  = session.state == "CLOSE_WAIT"
    deadline  = time.time() + 3
    
    #Trying to make sure that the sender got the FIN 
    while not (fin_acked and peer_fin) and time.time() < deadline:
        try: 
            q = get_packet_queue(client_key)
            packet, _ = q.get(timeout=0.5)
        except queue.Empty:
            if not fin_acked:
                send_FIN()
            continue
            
        ihl = (packet[0] & 0x0F) * 4
        tcp_packet = packet[ihl:]
        
        if len(tcp_packet) < 20:
            continue

        tcph = struct.unpack('!HHLLBBHHH', tcp_packet[:20])
        src_port, dest_port, pkt_seq, pkt_ack, flags = (
            tcph[0],
            tcph[1],
            tcph[2],
            tcph[3],
            tcph[5],
        )

        fin_flag = flags & 0x01
        ack_flag = (flags & 0x10) >> 4
            
        if ack_flag and pkt_ack >= session.server_seq + 1:
            fin_acked = True
        if fin_flag:
            peer_fin = True
            payload_len = len(tcp_packet) - ((tcp_packet[12] >> 4) * 4)
            ack_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                          seq=session.server_seq+1, ack_seq=pkt_seq + payload_len + 1, ack=1)
            ip_header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, len(ack_packet))
            s.sendto(ip_header + ack_packet, (client_ip, 0))
    
    # Clean up packet queue
    forget_connection(client_key)


def close_all_connections():
    """Close all connections and clean up."""
    with connections_lock:
        connections.clear()

def forget_connection(client_key):
    """Clean up utils"""
    from .streaprous_reliability import reorder_buffers  
    from .streaprous_flow_control import flow
    with connections_lock:
        connections.pop(client_key, None)
    remove_packet_queue(client_key)
    reorder_buffers.pop(client_key, None)
    flow.pop(client_key, None)