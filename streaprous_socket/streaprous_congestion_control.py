"""
StreapRous Congestion Control (CUBIC).

Moved unchanged from nalux's commit 9e7934b (streaprous_socket/transport_control.py,
branch feat/raw-socket-tcp) after PR #12 was reverted. Not wired into reliable_send yet:
the hook is the `cwnd` argument of usable(peer_rwnd, cwnd, snd_nxt, snd_una), which
reliable_send currently passes as float("inf").
"""
from __future__ import annotations

import time
from typing import Optional


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
