import sys
import types
import unittest
from unittest.mock import patch

# The raw-socket module imports netifaces at module load. These unit tests do
# not exercise interface discovery, so provide a minimal import-time stub.
sys.modules.setdefault("netifaces", types.ModuleType("netifaces"))

from daemon.httpadapter import HttpAdapter
from daemon.request import Request


class HttpStreamingTests(unittest.TestCase):
    def test_request_is_assembled_across_arbitrary_tcp_chunks(self):
        adapter = HttpAdapter(None, None, None, None, {})
        conn_info = object()
        chunks = [
            b"POST /submit-info HTTP/1.1\r\nHo",
            b"st: localhost\r\nContent-Length: 11\r\n",
            b"Content-Type: text/plain\r\n\r\nhello ",
            b"worldEXTRA",
        ]
        with patch("daemon.httpadapter.run_conn_recv", side_effect=chunks) as recv:
            message = adapter._receive_raw_http_request(None, conn_info)

        self.assertEqual(
            message,
            b"POST /submit-info HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Length: 11\r\nContent-Type: text/plain\r\n\r\nhello world",
        )
        self.assertEqual(recv.call_count, 4)

    def test_request_prepare_populates_headers_and_body(self):
        request = Request()
        request.prepare(
            "POST /send HTTP/1.1\r\nHost: localhost\r\n"
            "Content-Length: 5\r\nX-Test: yes\r\n\r\nhello",
            routes={},
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/send")
        self.assertEqual(request.headers["host"], "localhost")
        self.assertEqual(request.headers["content-length"], "5")
        self.assertEqual(request.body, "hello")

    def test_incomplete_body_is_rejected(self):
        adapter = HttpAdapter(None, None, None, None, {})
        chunks = [b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc", b""]
        with patch("daemon.httpadapter.run_conn_recv", side_effect=chunks):
            with self.assertRaises(ConnectionError):
                adapter._receive_raw_http_request(None, object())

    def test_chunked_body_is_explicitly_rejected(self):
        adapter = HttpAdapter(None, None, None, None, {})
        chunks = [b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"]
        with patch("daemon.httpadapter.run_conn_recv", side_effect=chunks):
            with self.assertRaises(ValueError):
                adapter._receive_raw_http_request(None, object())


if __name__ == "__main__":
    unittest.main()
