import unittest

from streaprous_socket.transport_control import (
    CubicController, FlowControlWindow, ReceiveReorderBuffer,
    ReliableSendBuffer, RttEstimator, seq_add, seq_lt,
)


class SequenceTests(unittest.TestCase):
    def test_wraparound(self):
        self.assertEqual(seq_add(0xFFFFFFFE, 4), 2)
        self.assertTrue(seq_lt(0xFFFFFFFE, 2))


class ReliabilityTests(unittest.TestCase):
    def test_cumulative_and_partial_ack(self):
        sender = ReliableSendBuffer(100)
        sender.add(b"hello", now=0)
        sender.add(b"world", now=0)
        acked, samples = sender.acknowledge(103, now=1)
        self.assertEqual(acked, 3)
        self.assertEqual(samples, [1])
        self.assertEqual(sender.bytes_in_flight, 7)
        remaining = list(sender._segments.values())
        self.assertEqual(remaining[0].seq, 103)
        self.assertEqual(remaining[0].data, b"lo")
        self.assertEqual(remaining[1].data, b"world")
        acked, samples = sender.acknowledge(110, now=2)
        self.assertEqual(acked, 7)
        self.assertEqual(len(samples), 1)  # at most one RTT sample per ACK
        self.assertEqual(sender.bytes_in_flight, 0)

    def test_stale_and_future_acknowledgements_are_ignored(self):
        sender = ReliableSendBuffer(100)
        sender.add(b"payload", now=0)
        self.assertEqual(sender.acknowledge(99, now=1), (0, []))
        self.assertEqual(sender.acknowledge(108, now=1), (0, []))
        self.assertEqual(sender.snd_una, 100)
        self.assertEqual(sender.bytes_in_flight, 7)

    def test_acknowledgement_across_sequence_wraparound(self):
        sender = ReliableSendBuffer(0xFFFFFFFC)
        sender.add(b"abcdef", now=10)
        self.assertEqual(sender.snd_nxt, 2)
        acked, samples = sender.acknowledge(0xFFFFFFFF, now=11)
        self.assertEqual(acked, 3)
        self.assertEqual(samples, [1])
        remaining = next(iter(sender._segments.values()))
        self.assertEqual(remaining.seq, 0xFFFFFFFF)
        self.assertEqual(remaining.data, b"def")
        acked, _ = sender.acknowledge(2, now=12)
        self.assertEqual(acked, 3)
        self.assertEqual(sender.bytes_in_flight, 0)

    def test_retransmitted_data_is_not_used_for_rtt_sample(self):
        sender = ReliableSendBuffer(10)
        sender.add(b"first", now=1)
        sender.due_for_retransmission(2, now=4)
        acked, samples = sender.acknowledge(15, now=5)
        self.assertEqual(acked, 5)
        self.assertEqual(samples, [])

    def test_only_oldest_segment_uses_single_retransmission_timer(self):
        sender = ReliableSendBuffer(0)
        first = sender.add(b"first", now=10)
        second = sender.add(b"second", now=11)
        due = sender.due_for_retransmission(2, now=12)
        self.assertEqual([segment.seq for segment in due], [first.seq])
        self.assertEqual(sender.due_for_retransmission(2, now=13), [])
        # ACKing the first segment restarts the timer for the next oldest one.
        sender.acknowledge(5, now=13)
        self.assertEqual(sender.due_for_retransmission(2, now=14), [])
        due = sender.due_for_retransmission(2, now=15)
        self.assertEqual([segment.seq for segment in due], [second.seq])

    def test_out_of_order_and_duplicate_suppression(self):
        receiver = ReceiveReorderBuffer(100, capacity=32)
        self.assertEqual(receiver.receive(105, b"world"), b"")
        self.assertEqual(receiver.receive(105, b"world"), b"")
        self.assertEqual(receiver.receive(100, b"hello"), b"helloworld")
        self.assertEqual(receiver.rcv_nxt, 110)

    def test_in_order_gap_fills_and_drains_existing_overlapping_segment(self):
        receiver = ReceiveReorderBuffer(100, capacity=32)
        self.assertEqual(receiver.receive(105, b"world"), b"")
        # The already-buffered bytes win on overlap (first arrival wins).
        self.assertEqual(receiver.receive(100, b"abcdefghij"), b"abcdeworld")
        self.assertEqual(receiver.rcv_nxt, 110)
        self.assertEqual(receiver.buffered_bytes, 0)
        self.assertEqual(receiver._pending, {})

    def test_partial_overlap_keeps_first_arrival_bytes_and_adds_missing_suffix(self):
        receiver = ReceiveReorderBuffer(100, capacity=32)
        self.assertEqual(receiver.receive(105, b"FGHIJ"), b"")
        # Incoming [100, 108) overlaps [105, 110); first arrival wins.
        self.assertEqual(receiver.receive(100, b"abcdeXXX"), b"abcdeFGHIJ")
        self.assertEqual(receiver.rcv_nxt, 110)

    def test_duplicate_prefix_is_trimmed(self):
        receiver = ReceiveReorderBuffer(100, capacity=32)
        self.assertEqual(receiver.receive(100, b"hello"), b"hello")
        self.assertEqual(receiver.receive(102, b"lloWORLD"), b"WORLD")
        self.assertEqual(receiver.rcv_nxt, 110)

    def test_out_of_order_partial_overlap_only_stores_missing_bytes(self):
        receiver = ReceiveReorderBuffer(100, capacity=32)
        self.assertEqual(receiver.receive(105, b"FGHIJ"), b"")
        self.assertEqual(receiver.receive(103, b"DEFG"), b"")
        self.assertEqual(receiver.buffered_bytes, 7)
        self.assertEqual(receiver.receive(100, b"abc"), b"abcDEFGHIJ")
        self.assertEqual(receiver.rcv_nxt, 110)

    def test_receive_buffer_capacity_applies_to_in_order_data(self):
        receiver = ReceiveReorderBuffer(100, capacity=4)
        self.assertEqual(receiver.receive(100, b"abcdef"), b"abcd")
        self.assertEqual(receiver.rcv_nxt, 104)
        self.assertEqual(receiver.buffered_bytes, 0)

    def test_retransmission_timeout(self):
        sender = ReliableSendBuffer(0)
        sender.add(b"abc", now=10)
        due = sender.due_for_retransmission(2, now=13)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0].data, b"abc")
        self.assertEqual(due[0].transmissions, 2)


class ControlTests(unittest.TestCase):
    def test_rtt_and_backoff(self):
        rtt = RttEstimator()
        self.assertGreater(rtt.sample(0.2), 0)
        before = rtt.rto
        self.assertEqual(rtt.backoff(), min(60.0, before * 2))

    def test_receiver_window_budget(self):
        window = FlowControlWindow(1000)
        self.assertEqual(window.send_budget(300, 800), 500)
        window.update(0)
        self.assertEqual(window.send_budget(0, 800), 0)

    def test_receiver_and_congestion_windows_are_both_measured_in_bytes(self):
        window = FlowControlWindow(10000)
        # Both limits are bytes: min(10000, 4000) - 1500 = 2500.
        self.assertEqual(window.send_budget(1500, 4000), 2500)
        # Receiver window is now the tighter limit: 2000 - 1500 = 500.
        window.update(2000)
        self.assertEqual(window.send_budget(1500, 4000), 500)

    def test_cubic_window_is_stored_and_updated_in_bytes(self):
        cc = CubicController(mss=1000)
        self.assertEqual(cc.cwnd, 4000)  # initial window: 4 MSS = 4000 bytes
        self.assertEqual(cc.on_ack(now=1), 5000)  # one full-MSS ACK adds 1000 bytes
        self.assertEqual(cc.on_ack(now=1, acked_bytes=250), 5250)
        after_loss = cc.on_loss()
        self.assertAlmostEqual(after_loss, 3675)  # beta=0.7, still in bytes
        self.assertAlmostEqual(cc.ssthresh, 3675)

    def test_cubic_bounds_and_loss(self):
        cc = CubicController(mss=1000)
        for _ in range(100):
            cc.on_ack(now=1)
        self.assertLessEqual(cc.cwnd, 64000)
        after_loss = cc.on_loss()
        self.assertGreaterEqual(after_loss, 1000)
        self.assertLessEqual(after_loss, 64000)


if __name__ == "__main__":
    unittest.main()
