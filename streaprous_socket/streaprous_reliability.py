from streaprous_socket.streaprous_raw_connection import (
    connections, connections_lock, build_tcp_packet, build_ip_header, conn_struct
)
from streaprous_socket.streaprous_packet_struct import (
    pack_tcp_header, unpack_tcp_header, compute_tcp_checksum
)
from streaprous_socket.streaprous_packet_dispatcher import get_packet_queue, remove_packet_queue

from streaprous_socket.streaprous_flow_control import (
    RCV_BUF, flow, usable, probe_gave_up, should_probe, PROBE_INTERVAL, current_rwnd, classify, rwnd
)
from streaprous_socket.streaprous_congestion_control import CubicController
from collections import deque

import socket
import struct
import time
import queue
from collections import namedtuple
reorder_buffers = {}
congestion = {}         # one CUBIC controller per connection, kept between sends
def reliable_send( sock, src_ip, dest_ip, src_port, dst_port, seq, ack_seq,
        payload, auto_chunk=True, mss=1460, flags=0x18, rcv_wnd=RCV_BUF):
    """sends data reliably over a TCP-like connection using a custom implementation of the TCP protocol.
    Args:
            sock      (socket.socket): Raw socket instance
            src_ip    (str): Source IP address
            dest_ip   (str): Destination IP address
            src_port  (int): Source port
            dst_port  (int): Destination port
            seq       (int): Initial sequence number
            ack_seq   (int): Acknowledgement number
            payload   (bytes or bytearray): Data payload to transmit
            auto_chunk(bool): If True, automatically fragment data into mss-sized chunks
            mss       (int): Maximum Segment Size (default: 1460 bytes)
            flags     (int): TCP flags (default: 0x18 -> PSH + ACK)
            rcv_wnd    (int): TCP window size
            
        Returns:
            tuple: (total_sent, next_seq)"""
    if not isinstance(payload, (bytes, bytearray, memoryview)):
            payload = payload.encode('utf-8') if isinstance(payload, str) else bytes(payload)

    data_mv = memoryview(payload)
    total_sent = 0
    current_seq = seq
    pkt_queue= get_packet_queue((dest_ip, dst_port))  # Retrieve the global packet queue
    send_queue = deque() 
    oldest_unacked= seq
    key = (dest_ip, dst_port)
    cc = congestion.setdefault(key, CubicController(mss=mss))
    offset = 0
    offset_res = (5 << 4) + 0
    urg_ptr = 0
    
                
    def make_segment(seq_no, data):
        draft = pack_tcp_header(src_port, dst_port, seq_no, ack_seq, offset_res, flags, rcv_wnd, 0, urg_ptr)
        csum = compute_tcp_checksum(src_ip, dest_ip, draft, data)
        hdr = pack_tcp_header(src_port, dst_port, seq_no, ack_seq, offset_res, flags, rcv_wnd, csum, urg_ptr)
        return build_ip_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(hdr) + len(data)) + hdr + data

    timeout = 1.0  # Timeout in second
    retries = 0
    dup_acks = 0
    deadline = time.time() + timeout
    while offset < len(data_mv) or send_queue:                             
        cwnd = int(cc.cwnd) // mss * mss       # whole packets only, avoids tiny segments
        can = usable(flow[key]["peer_rwnd"], cwnd, current_seq, oldest_unacked)
        if can == 0 and not send_queue: 
            st = flow[key]
            while st["peer_rwnd"] == 0:
                if probe_gave_up(st["unanswered_probes"]):
                    raise ConnectionError("[Streap_flctrl] Probe limit exceeded")
                now = time.time()
                if not should_probe(st["peer_rwnd"], 0, st["last_probe"], now):
                    time.sleep(st["last_probe"] + PROBE_INTERVAL - now)
                    continue
                sock.sendto(make_segment(current_seq, data_mv[offset:offset + 1].tobytes()), (dest_ip, 0))
                st["last_probe"] = now
                st["unanswered_probes"]+=1
                print(f"[Streap_flctrl] zero window, probe {st['unanswered_probes']} at seq={current_seq}")       
                
                try:
                    packet, _ = pkt_queue.get(timeout=PROBE_INTERVAL)
                except queue.Empty:
                    continue
                tcp = unpack_tcp_header(packet[(packet[0] & 0x0F) * 4:])
                st["peer_rwnd"] = tcp['window']
                st["unanswered_probes"] = 0
                if tcp['ack_seq'] > current_seq:
                    offset += 1
                    total_sent += 1
                    current_seq += 1
                    oldest_unacked = current_seq
                continue  
            continue
        if offset < len(data_mv) and can > 0:        
            size = min(mss, can, len(data_mv) - offset)
            chunk_bytes = data_mv[offset:offset + size].tobytes()

            offset += size
            
            full_packet = make_segment(current_seq, chunk_bytes)
            sock.sendto(full_packet, (dest_ip, 0))
            send_queue.append((current_seq,full_packet, len(chunk_bytes)))
            total_sent += len(chunk_bytes)
            current_seq += len(chunk_bytes)

            if len(send_queue) == 1:
                    deadline = time.time() + timeout
            continue
        if send_queue:
            try:
                packet, _ = pkt_queue.get(timeout=max(0, deadline - time.time()))
            except queue.Empty:
                if retries > 10:
                    raise ConnectionError(f"no ACK for seq={send_queue[0][0]} after 10 retries")
                print(f"[Streap_RDT] Timeout for seq={send_queue[0][0]}, resending...")
                dup_acks = 0
                sock.sendto(send_queue[0][1], (dest_ip, 0))
                cc.on_loss()
                retries += 1
                deadline = time.time() + timeout
                continue                                   # timer ran out
            ihl = (packet[0] & 0x0F) * 4
            tcp = unpack_tcp_header(packet[ihl:])
            
            st = flow[key]
            st["peer_rwnd"] = tcp['window']
            st["unanswered_probes"] = 0
                        
            if tcp['ack_seq'] > oldest_unacked:      # client acked some data
                while send_queue and send_queue[0][0]+send_queue[0][2] <= tcp['ack_seq']: 
                    send_queue.popleft()
                retries = 0
                cc.on_ack(acked_bytes=tcp['ack_seq'] - oldest_unacked)
                oldest_unacked = tcp['ack_seq']
                dup_acks = 0
                deadline = time.time() + timeout
                continue                                

            if tcp['ack_seq'] == oldest_unacked:      # client still asking for this chunk
                dup_acks += 1
                if dup_acks == 3:
                    print(f"[Streap_RDT] 3 dup ACKs for seq={send_queue[0][0]}, fast retransmit")
                    sock.sendto(send_queue[0][1], (dest_ip, 0))
                    cc.on_loss()
                    deadline = time.time() + timeout
                    continue

            # any other packet (old ACK, etc.): ignore and keep waiting

    print(f"[Streap_RDT] Sent {total_sent} bytes, next_seq={current_seq}")
    return total_sent, current_seq
            

#Time out handling for streaprous reliability

#Retransmission when 3 acknowledgements of the same ack_num are received.

#Reciver's handling of out of order packets.
def reliable_receive(s: socket.socket, conn_info: conn_struct) -> bytes:
    """
        Receive data on an established connection using raw sockets.
        This function handles incoming packets for a specific connection by reading
        from the packet dispatcher's per-connection queue.
        
        Args:
            s: raw socket
            conn_info: conn_struct tuple for the connection
        
        Returns:
            bytes: The received data payload, or empty bytes if connection closed
    """
    client_ip = conn_info.client_ip
    client_port = conn_info.client_port
    client_key = (client_ip, client_port)
    listen_ip = conn_info.server_ip
    listen_port = conn_info.server_port
    
        
        # Get the packet queue for this connection from the dispatcher
    packet_queue = get_packet_queue(client_key)
        
    print(f"[Streap_raw] run_conn_recv: Starting receive loop for {client_ip}:{client_port} (waiting for data...)")
        
    try:
        while True:
            # Get packet from the dispatcher queue instead of reading directly from socket
            
            st = flow.get(client_key)
            if st is None:
                return b""
            
            try:
                if (st["rcv_buffer"]):
                    packet, addr = packet_queue.get_nowait()
                else:
                    packet, addr = packet_queue.get(timeout=1.0)
            except queue.Empty:
                if (st["rcv_buffer"]):
                    return None
                continue
            
            
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

            # Check if this packet is for our connection
            if src_port != client_port:
                continue
            
            syn_flag = (flags & 0x02) >> 1
            ack_flag = (flags & 0x10) >> 4
            psh_flag = (flags & 0x08) >> 3
            fin_flag = (flags & 0x01)
            rst_flag = (flags & 0x04) >> 2

            print(f"[Streap_raw] run_conn_recv: Received packet from {client_ip}:{client_port} (SYN={syn_flag}, ACK={ack_flag}, PSH={psh_flag}, FIN={fin_flag}, RST={rst_flag}, Seq={pkt_seq}, Ack={pkt_ack})")

            with connections_lock:
                if client_key not in connections:
                    continue
                session = connections[client_key]


            # Handle RST (connection reset)
            if rst_flag:
                print(f"[Streap_raw] Received RST from {client_ip}:{client_port}")
                with connections_lock:
                    if client_key in connections:
                        del connections[client_key]
                # Clean up packet queue
                from .streaprous_raw_connection import forget_connection
                forget_connection(client_key)
                
                return b""

            # Update last activity
            with connections_lock:
                if client_key in connections:
                    connections[client_key] = session._replace(last_activity=time.time())

            # Handle data payload (PSH + ACK) or (ACK with data) - Fast path ACK
            # Some clients may not set PSH flag for small requests
            has_data = len(tcp_packet) > ((tcp_packet[12] >> 4) & 0x0F) * 4
            
            if (psh_flag and ack_flag) or (ack_flag and has_data and not syn_flag and not rst_flag):
                # Dynamically look up header length to bypass any incoming TCP Options
                tcp_header_len = ((tcp_packet[12] >> 4) & 0x0F) * 4
                app_payload = tcp_packet[tcp_header_len:]
                
                if len(app_payload) > 0:
                    expected = session.client_seq
                    buf = reorder_buffers.setdefault(client_key, {})
                    data = b""
                    #Pure function used to delegate responsibility for Flow Control
                    # Drop duplicates and segments beyond the receive window.
                    type = classify(pkt_seq, len(app_payload), expected, rwnd(RCV_BUF, expected, st["next_to_read"]))

                    if type == "in_order":                 # in order -> deliver + pull from buffer
                        data = app_payload
                        expected += len(app_payload)
                        while expected in buf:
                            nxt = buf.pop(expected)
                            data += nxt
                            expected += len(nxt)
                        st["rcv_buffer"] += data
                    elif type == "hold":                # gap -> hold it
                        buf[pkt_seq] = app_payload
                        print(f"[Streap_RDT] Out of order seq={pkt_seq}, want {expected}, buffered")
                    else:                                   # old duplicate -> drop
                        print(f"[Streap_RDT] Duplicate seq={pkt_seq}, ignored")

                    # Always ACK the next byte we want (cumulative ACK)
                    header=build_ip_header(session.server_ip, client_ip, socket.IPPROTO_TCP, 20)
                    ack_packet = build_tcp_packet(session.server_ip, client_ip, listen_port, client_port,
                                                  seq=session.server_seq, ack_seq=expected, ack=1, rcv_wnd=current_rwnd(client_key, expected))
                    s.sendto(header + ack_packet, (client_ip, 0))

                    with connections_lock:
                        if client_key in connections:
                            connections[client_key] = session._replace(
                                client_seq=expected, last_activity=time.time())


            # Handle FIN (connection close)
            # Ensure that the FIN check only works after data is handled, preventing data lost
            if fin_flag:             
                
                plen = len(tcp_packet) - ((tcp_packet[12] >> 4) & 0x0F) * 4
                with connections_lock:
                    session = connections.get(client_key)  
                if session and pkt_seq + plen == session.client_seq: 
                    fin_ack = session.client_seq + 1
                    with connections_lock:
                        connections[client_key] = session._replace(state="CLOSE_WAIT", client_seq=fin_ack)
                    header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, 20)
                    ack_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                                seq=session.server_seq, ack_seq=fin_ack, ack=1)
                    s.sendto(header + ack_packet, (client_ip, 0))
                    return None if st["rcv_buffer"] else b""
            
            # Handle pure ACK (no data)
            #FIN was previously handled here, which is before data processing and might result in data loss, so it's handled above
            elif ack_flag and not syn_flag and not psh_flag and not has_data:
                print(f"[Streap_raw] Received ACK from {client_ip}:{client_port} (Ack={pkt_ack})")
                with connections_lock:
                    if client_key in connections:
                        connections[client_key] = session._replace(
                            server_seq=pkt_ack,
                            last_activity=time.time()
                        )
                #Probe ACK
                if (pkt_seq < session.client_seq):
                    header = build_ip_header(listen_ip, client_ip, socket.IPPROTO_TCP, 20)
                    ack_packet = build_tcp_packet(listen_ip, client_ip, listen_port, client_port,
                                                seq=session.server_seq, ack_seq=session.client_seq, ack=1, rcv_wnd=current_rwnd(client_key, session.client_seq))
                    s.sendto(header + ack_packet, (client_ip, 0))
                

    except KeyboardInterrupt:
        print("\n[Streap_raw] Receive loop interrupted.")
        return b""
    except Exception as e:
        print(f"[Streap_raw] Error in run_conn_recv: {e}")
        return b""