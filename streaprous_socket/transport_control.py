"""Transport-layer state helpers for StreApRous (educational TCP-like stack).

This module is deliberately independent of raw-socket I/O so its state machines
can be unit-tested without root privileges or a live network interface.
Sequence numbers are 32-bit TCP byte sequence numbers.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import time
from typing import Optional

SEQ_MOD = 1 << 32
SEQ_MASK = SEQ_MOD - 1
SEQ_HALF = 1 << 31


def seq_add(seq: int, amount: int) -> int:
    return (seq + amount) & SEQ_MASK


def seq_lt(a: int, b: int) -> bool:
    """True when a is before b in TCP's modular sequence space."""
    return a != b and ((b - a) & SEQ_MASK) < SEQ_HALF


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


@dataclass
class OutstandingSegment:
    seq: int
    data: bytes
    sent_at: float
    transmissions: int = 1

    @property
    def end_seq(self) -> int:
        return seq_add(self.seq, len(self.data))


class ReliableSendBuffer:
    """Tracks unacknowledged bytes and supports cumulative/partial ACKs + Fast Retransmit."""
    def __init__(self, initial_seq: int = 0):
        self.snd_una = initial_seq & SEQ_MASK
        self.snd_nxt = initial_seq & SEQ_MASK
        self._segments: OrderedDict[int, OutstandingSegment] = OrderedDict()
        # TCP uses one retransmission timer for the oldest unacknowledged data.
        self._timer_started_at: Optional[float] = None
        self.dup_ack_count: int = 0
        self._last_ack_window: Optional[int] = None

    @property
    def bytes_in_flight(self) -> int:
        return sum(len(s.data) for s in self._segments.values())

    def add(self, data: bytes, now: Optional[float] = None) -> OutstandingSegment:
        if not data:
            raise ValueError("TCP data segment must not be empty")
        now = time.monotonic() if now is None else now
        segment = OutstandingSegment(self.snd_nxt, bytes(data), now)
        self._segments[segment.seq] = segment
        self.snd_nxt = seq_add(self.snd_nxt, len(data))
        if self._timer_started_at is None:
            self._timer_started_at = now
        return segment

    def acknowledge(self, ack: int, now: Optional[float] = None,
                    window: Optional[int] = None) -> tuple[int, list[float]]:
        """Apply a valid cumulative ACK; return (newly_acked_bytes, RTT samples).

        ACKs outside [SND.UNA, SND.NXT] are ignored. Partial ACKs trim the
        acknowledged prefix. At most one RTT sample is taken per ACK, and only
        from data that has never been retransmitted (Karn's algorithm).
        """
        ack &= SEQ_MASK
        now = time.monotonic() if now is None else now
        if ack == self.snd_una or seq_lt(ack, self.snd_una) or seq_lt(self.snd_nxt, ack):
            return 0, []

        newly_acked = (ack - self.snd_una) & SEQ_MASK
        remaining = newly_acked
        rtt_sample = None
        for key, seg in list(self._segments.items()):
            if remaining <= 0:
                break
            acknowledged_from_segment = min(remaining, len(seg.data))
            if rtt_sample is None and seg.transmissions == 1:
                rtt_sample = max(0.0, now - seg.sent_at)
            remaining -= acknowledged_from_segment
            del self._segments[key]
            if acknowledged_from_segment < len(seg.data):
                seg.seq = seq_add(seg.seq, acknowledged_from_segment)
                seg.data = seg.data[acknowledged_from_segment:]
                self._segments[seg.seq] = seg
                self._segments.move_to_end(seg.seq, last=False)

        self.snd_una = ack
        self.dup_ack_count = 0
        if window is not None:
            self._last_ack_window = window
        self._timer_started_at = now if self._segments else None
        return newly_acked, ([rtt_sample] if rtt_sample is not None else [])

    def on_duplicate_ack(self, ack: int, window: int, has_payload: bool = False,
                         syn_or_fin: bool = False,
                         now: Optional[float] = None) -> Optional[OutstandingSegment]:
        """Track duplicate ACKs per RFC 5681; return oldest segment on the 3rd dup ACK."""
        ack &= SEQ_MASK
        now = time.monotonic() if now is None else now
        if ack != self.snd_una or not self._segments:
            return None

        # Pure window-update ACKs or packets carrying data/SYN/FIN are not duplicate ACKs.
        if has_payload or syn_or_fin or (self._last_ack_window is not None and window != self._last_ack_window):
            self.dup_ack_count = 0
            self._last_ack_window = window
            return None

        self._last_ack_window = window
        self.dup_ack_count += 1
        if self.dup_ack_count == 3:
            segment = next(iter(self._segments.values()))
            segment.sent_at = now
            segment.transmissions += 1
            self._timer_started_at = now
            return segment
        return None

    def due_for_retransmission(self, rto: float, now: Optional[float] = None) -> list[OutstandingSegment]:
        """Return only the oldest segment when the single RTO timer expires."""
        now = time.monotonic() if now is None else now
        if not self._segments or self._timer_started_at is None:
            return []
        if now - self._timer_started_at < rto:
            return []

        segment = next(iter(self._segments.values()))
        segment.sent_at = now
        segment.transmissions += 1
        self._timer_started_at = now
        return [segment]


class ReceiveReorderBuffer:
    """Buffers out-of-order bytes and exposes only contiguous stream data."""
    def __init__(self, initial_seq: int = 0, capacity: int = 65535):
        self.rcv_nxt = initial_seq & SEQ_MASK
        self.capacity = max(0, capacity)
        self._pending: dict[int, bytes] = {}
        self._ready = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._ready) + sum(map(len, self._pending.values()))

    @property
    def advertised_window(self) -> int:
        return max(0, self.capacity - self.buffered_bytes)

    def receive(self, seq: int, data: bytes) -> bytes:
        """Accept stream bytes, preserving first-arrival data on overlaps."""
        if not data or self.capacity == 0:
            return self.read()

        seq &= SEQ_MASK
        payload = bytes(data)

        if seq_lt(seq, self.rcv_nxt):
            duplicate_prefix = (self.rcv_nxt - seq) & SEQ_MASK
            if duplicate_prefix >= len(payload):
                return self.read()
            payload = payload[duplicate_prefix:]
            seq = self.rcv_nxt

        offset = (seq - self.rcv_nxt) & SEQ_MASK
        if offset >= SEQ_HALF:
            return self.read()

        incoming_start = offset
        incoming_end = offset + len(payload)

        occupied = []
        for pending_seq, pending_data in self._pending.items():
            pending_offset = (pending_seq - self.rcv_nxt) & SEQ_MASK
            if pending_offset < SEQ_HALF:
                occupied.append((pending_offset, pending_offset + len(pending_data)))
        occupied.sort()

        cursor = incoming_start
        available = self.capacity - self.buffered_bytes
        for start, end in occupied + [(incoming_end, incoming_end)]:
            if cursor >= incoming_end or available <= 0:
                break
            if end <= cursor:
                continue
            if start > cursor:
                gap_end = min(start, incoming_end)
                gap_end = min(gap_end, cursor + available)
                part = payload[cursor - incoming_start:gap_end - incoming_start]
                if part:
                    self._pending[seq_add(self.rcv_nxt, cursor)] = part
                    available -= len(part)
                cursor = gap_end
            cursor = max(cursor, min(end, incoming_end))

        while self.rcv_nxt in self._pending:
            chunk = self._pending.pop(self.rcv_nxt)
            self._ready.extend(chunk)
            self.rcv_nxt = seq_add(self.rcv_nxt, len(chunk))

        return self.read()

    def read(self, size: Optional[int] = None) -> bytes:
        if size is None or size < 0:
            size = len(self._ready)
        n = min(size, len(self._ready))
        result = bytes(self._ready[:n])
        del self._ready[:n]
        return result


class RttEstimator:
    """RFC-6298-style SRTT/RTTVAR estimator with exponential backoff."""
    def __init__(self, initial_rto: float = 1.0, min_rto: float = 1.0, max_rto: float = 60.0):
        self.srtt: Optional[float] = None
        self.rttvar: Optional[float] = None
        self.min_rto, self.max_rto = min_rto, max_rto
        self.rto = initial_rto

    def sample(self, measured_rtt: float) -> float:
        if measured_rtt <= 0:
            return self.rto
        if self.srtt is None:
            self.srtt = measured_rtt
            self.rttvar = measured_rtt / 2
        else:
            assert self.rttvar is not None
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - measured_rtt)
            self.srtt = 0.875 * self.srtt + 0.125 * measured_rtt
        self.rto = min(self.max_rto, max(self.min_rto, self.srtt + max(0.01, 4 * self.rttvar)))
        return self.rto

    def backoff(self) -> float:
        self.rto = min(self.max_rto, self.rto * 2)
        return self.rto


class FlowControlWindow:
    """Receiver-advertised window in bytes; all send limits use bytes."""
    def __init__(self, rwnd: int = 5840):
        self.rwnd = max(0, int(rwnd))

    def update(self, advertised_window: int) -> None:
        self.rwnd = max(0, min(65535, int(advertised_window)))

    def send_budget(self, bytes_in_flight: int, cwnd: int) -> int:
        effective_limit = min(self.rwnd, max(0, int(cwnd)))
        return max(0, effective_limit - max(0, int(bytes_in_flight)))


class CubicController:
    """Compact CUBIC controller whose public congestion window is in bytes."""
    def __init__(self, initial_cwnd: Optional[float] = None,
                 ssthresh: Optional[float] = None, C: float = 0.4,
                 beta: float = 0.7, min_cwnd: Optional[float] = None,
                 max_cwnd: Optional[float] = None, mss: int = 1400):
        if mss <= 0:
            raise ValueError("MSS must be positive")
        self.mss = int(mss)
        self.cwnd = float(4 * self.mss if initial_cwnd is None else initial_cwnd)
        self.ssthresh = float(64 * self.mss if ssthresh is None else ssthresh)
        self.C, self.beta = C, beta
        self.min_cwnd = float(self.mss if min_cwnd is None else min_cwnd)
        self.max_cwnd = float(64 * self.mss if max_cwnd is None else max_cwnd)
        self.w_max = self.cwnd
        self.epoch_start: Optional[float] = None
        self.k = 0.0
        self.origin = self.cwnd

    def on_ack(self, now: Optional[float] = None,
               acked_bytes: Optional[int] = None) -> float:
        now = time.monotonic() if now is None else now
        acknowledged = self.mss if acked_bytes is None else max(0, int(acked_bytes))
        if acknowledged == 0:
            return self.cwnd
        acked_segments = acknowledged / self.mss
        cwnd_segments = self.cwnd / self.mss
        ssthresh_segments = self.ssthresh / self.mss
        if cwnd_segments < ssthresh_segments:  # Slow Start
            cwnd_segments += acked_segments
        else:  # CUBIC Congestion Avoidance
            if self.epoch_start is None:
                self.epoch_start = now
                self.origin = max(self.cwnd, self.w_max)
                w_max_segments = self.w_max / self.mss
                self.k = ((w_max_segments * (1 - self.beta)) / self.C) ** (1 / 3) if w_max_segments > 0 else 0
            t = max(0.0, now - self.epoch_start)
            origin_segments = self.origin / self.mss
            target = self.C * (t - self.k) ** 3 + origin_segments
            per_segment_growth = max(
                1 / max(cwnd_segments, 1),
                (target - cwnd_segments) / max(cwnd_segments, 1),
            )
            cwnd_segments += per_segment_growth * acked_segments
        self.cwnd = min(
            self.max_cwnd,
            max(self.min_cwnd, cwnd_segments * self.mss),
        )
        return self.cwnd

    def on_loss(self) -> float:
        self.w_max = self.cwnd
        self.cwnd = max(self.min_cwnd, self.cwnd * self.beta)
        self.ssthresh = self.cwnd
        self.epoch_start = None
        return self.cwnd