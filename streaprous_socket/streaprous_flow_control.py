"""Flow control was put on a standalone file for ease of testing and debugging. Also prevent circular imports"""


MAX_WINDOW = 65535      # 16-bit window field, maximum 2^16
RCV_BUF = 65535
PROBE_INTERVAL = 0.1    # 100ms
PROBE_LIMIT = 50        # about 5 seconds
MSS = 1460

flow = {}

#receiver side

def current_rwnd(key, client_seq):
    st = flow.get(key)
    if st:
        free = rwnd(RCV_BUF, client_seq, st["next_to_read"])      
        if (free < min(MSS, RCV_BUF // 2)): #Handle silly window syndrome
            return 0
        return free 
    return RCV_BUF

def rwnd(rcv_buf, client_seq, next_to_read):
    """
    Window to advertise to the client.
    Simple formula: rwnd = rcv_buf - (client_seq - next_to_read)
    """
    
    rwnd = rcv_buf - (client_seq - next_to_read)
    rwnd = min(MAX_WINDOW, rwnd)
    rwnd = max(0, rwnd)
    
    return rwnd


def classify(seg_seq, seg_len, client_seq, window):
    """
    Decide what to do with an incoming data segment.
    :return:
        "dup"       segment ends at or before client_seq (duplicated): drop
        "beyond"    segment ends past client_seq + window: drop
        "in_order"  segment starts at client_seq: buffer it, then pull held segments
        "hold"      packet arrived early: keep in the reorder buffer
    """
    
    if (seg_seq < client_seq):
        return "dup"
    if (seg_seq + seg_len > client_seq + window):
        return "beyond"
    if (seg_seq == client_seq):
        return "in_order"
    return "hold" #Segment arrived early
    

def need_window_update(old_rwnd, new_rwnd):
    return (old_rwnd == 0) and (new_rwnd > 0)


#sender side

def usable(peer_rwnd, cwnd, snd_nxt, snd_una):
    """
    Bytes we may send right now.
    """
    can_send = min(peer_rwnd, cwnd) - (snd_nxt - snd_una)
    return max(0, can_send)


def should_probe(peer_rwnd, in_flight, last_probe_time, now):
    return (last_probe_time + PROBE_INTERVAL < now) and (peer_rwnd == 0) and (in_flight == 0)


def probe_gave_up(unanswered_probes):
    return unanswered_probes >= PROBE_LIMIT;
