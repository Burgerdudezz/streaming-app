import queue
import threading
import unittest
from unittest.mock import patch

import streaprous_socket.streaprous_raw_connection as raw
from streaprous_socket.streaprous_raw_connection import (
    _valid_final_ack, _receive_payload, _take_unread, _advertised_window
)
from streaprous_socket.transport_control import (
    ReceiveReorderBuffer, ReliableSendBuffer, FlowControlWindow,
    CubicController, RttEstimator,
)


class RawConnectionStateTests(unittest.TestCase):
    def make_state(self, capacity=8, initial_seq=100):
        return {
            "lock": threading.RLock(),
            "receiver": ReceiveReorderBuffer(initial_seq=initial_seq, capacity=capacity),
            "unread": bytearray(),
        }

    def test_final_handshake_ack_checks_seq_and_ack(self):
        self.assertTrue(_valid_final_ack(101, 100, 501, 501))
        self.assertFalse(_valid_final_ack(102, 100, 501, 501))
        self.assertFalse(_valid_final_ack(101, 100, 502, 501))

    def test_receive_payload_moves_contiguous_bytes_to_unread(self):
        state = self.make_state()
        _receive_payload(state, 100, b"hello")
        self.assertEqual(bytes(state["unread"]), b"hello")
        self.assertEqual(state["receiver"].buffered_bytes, 0)
        self.assertEqual(_take_unread(state), b"hello")
        self.assertEqual(_take_unread(state), b"")

    def test_handshake_payload_is_saved_for_application(self):
        key = ("192.0.2.12", 40002)
        fake_socket = type("FakeSocket", (), {"sendto": lambda self, data, addr: None})()
        with patch.object(raw, "build_tcp_packet", return_value=b"tcp"), \
             patch.object(raw, "build_ip_header", return_value=b"ip"):
            raw._init_established_session(
                fake_socket, key, "192.0.2.1", 9000,
                101, 701, 32, 701, b"hello"
            )
        try:
            self.assertEqual(bytes(raw._conn_states[key]["unread"]), b"hello")
            self.assertEqual(raw._advertised_window(raw._conn_states[key]),
                             raw.RECEIVE_CAPACITY - 5)
        finally:
            raw.connections.pop(key, None)
            raw._conn_states.pop(key, None)
            raw.remove_packet_queue(key)

    def test_unread_bytes_consume_advertised_receive_window(self):
        state = self.make_state(capacity=8)
        _receive_payload(state, 100, b"123456")
        self.assertEqual(_advertised_window(state), 2)
        self.assertEqual(_take_unread(state), b"123456")
        self.assertEqual(_advertised_window(state), 8)

    def test_unread_capacity_limits_new_incoming_data(self):
        state = self.make_state(capacity=8)
        _receive_payload(state, 100, b"123456")
        # Only two more bytes fit until the app consumes the first six.
        _receive_payload(state, 106, b"abcdef")
        self.assertEqual(bytes(state["unread"]), b"123456ab")
        self.assertEqual(_advertised_window(state), 0)

    def test_out_of_order_data_is_not_delivered_early(self):
        state = self.make_state(capacity=8)
        _receive_payload(state, 103, b"def")
        self.assertEqual(bytes(state["unread"]), b"")
        self.assertEqual(_advertised_window(state), 5)
        _receive_payload(state, 100, b"abc")
        self.assertEqual(_take_unread(state), b"abcdef")

    def test_run_conn_recv_returns_unread_and_advertises_freed_window(self):
        key = ("192.0.2.10", 40000)
        session = raw.conn_struct(key[0], key[1], "192.0.2.1", 9000,
                                  "ESTABLISHED", 700, 105, 701, 0)
        state = self.make_state(capacity=8, initial_seq=105)
        state.update({
            "sender": ReliableSendBuffer(initial_seq=700),
            "flow": FlowControlWindow(rwnd=8),
            "congestion": CubicController(mss=raw.TCP_MSS),
            "rtt": RttEstimator(),
        })
        state["unread"].extend(b"hello")
        raw.connections[key] = session
        raw._conn_states[key] = state
        try:
            with patch.object(raw, "_send_ack_only") as send_ack:
                result = raw.run_conn_recv(object(), session)
            self.assertEqual(result, b"hello")
            send_ack.assert_called_once()
            self.assertEqual(send_ack.call_args.kwargs["window"], 8)
        finally:
            raw.connections.pop(key, None)
            raw._conn_states.pop(key, None)

    def test_run_conn_send_preserves_peer_data_received_while_waiting_for_ack(self):
        key = ("192.0.2.11", 40001)
        session = raw.conn_struct(key[0], key[1], "192.0.2.1", 9000,
                                  "ESTABLISHED", 700, 100, 701, 0)
        state = self.make_state(capacity=32, initial_seq=100)
        state.update({
            "sender": ReliableSendBuffer(initial_seq=700),
            "flow": FlowControlWindow(rwnd=32),
            "congestion": CubicController(mss=raw.TCP_MSS),
            "rtt": RttEstimator(),
        })
        packets = queue.Queue()
        packets.put((b"fake", None))
        raw.connections[key] = session
        raw._conn_states[key] = state
        try:
            # The incoming packet both acknowledges our 3-byte send and carries
            # peer application data. This is the exact interleaving that used to
            # be lost when receiver.receive()'s return value was ignored.
            with patch.object(raw, "get_packet_queue", return_value=packets), \
                 patch.object(raw, "_decode_packet", return_value=(40001, 9000, 100, 703, 0x10, 32, b"reply")), \
                 patch.object(raw, "send_tcp_data_segment"), \
                 patch.object(raw, "_send_ack_only"), \
                 patch.object(raw, "_touch_connection"):
                sent = raw.run_conn_send(object(), session, b"req")
            self.assertEqual(sent, 3)
            self.assertEqual(bytes(state["unread"]), b"reply")
        finally:
            raw.connections.pop(key, None)
            raw._conn_states.pop(key, None)


if __name__ == "__main__":
    unittest.main()
