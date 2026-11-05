"""Tests for what burst.py takes as a valid run: python3 -m unittest test_burst"""
import socket
import threading
import time
import unittest

import burst


class TakeHeaderTest(unittest.TestCase):
    def test_header_in_pieces(self):
        # The status line and the end of the header each split across reads:
        # nothing before the end counts as body.
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789"
        for cut in range(1, len(response)):
            head, body = b"", 0
            for chunk in (response[:cut], response[cut:]):
                if head is None:
                    body += len(chunk)
                    continue
                head, n = burst.take_header(head, chunk)
                body += n
            self.assertIsNone(head, f"cut at {cut}: header never ended")
            self.assertEqual(body, 10, f"cut at {cut}: {body} body bytes")

    def test_status(self):
        with self.assertRaises(OSError):
            burst.take_header(b"", b"HTTP/1.1 503 Busy\r\n\r\n")


class OutsideTest(unittest.TestCase):
    def serve(self, feed):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)

        def accept():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=feed, args=(c,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        self.addCleanup(srv.close)
        return srv.getsockname()

    def test_early_eof_is_no_flow(self):
        # Peers that close at once are not outside load.
        addr = self.serve(lambda c: c.close())
        connected = []
        burst.outside(4, 1.0, connected, addr)
        self.assertEqual(len(connected), 4)
        self.assertTrue(all(err for _, _, err in connected), connected)

    def test_flow_to_its_deadline(self):
        def feed(c):
            try:
                while True:
                    c.sendall(bytes(1 << 14))
                    time.sleep(0.01)
            except OSError:
                pass
        addr = self.serve(feed)
        connected = []
        start = time.time()
        burst.outside(2, 0.5, connected, addr)
        self.assertGreaterEqual(time.time() - start, 0.5)
        self.assertEqual(len(connected), 2)
        for got, took, err in connected:
            self.assertIsNone(err)
            self.assertGreater(got, 0)


if __name__ == "__main__":
    unittest.main()
