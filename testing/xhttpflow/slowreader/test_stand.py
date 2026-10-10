"""Tests for stand.py that need no root, network or real processes: the
clock, sockets and subprocesses are fakes.

  cd testing/xhttpflow/slowreader && python3 -B -m unittest test_stand
"""
import socket
import types
import unittest
from unittest import mock

import stand

SOCKS_METHOD_REPLY = b"\x05\x00"
SOCKS_CONNECT_REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x46\x50"
PONG = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong"


class Clock:
    def __init__(self):
        self.now = 100.0

    def time(self):
        return self.now


class ScriptedSocket:
    """A socket whose peer answers each recv after a delay on the fake clock,
    and whose sends each take send_delay. An operation that would wait longer
    than the timeout in effect times out, as a real one does. Every operation
    is checked against the request's deadline: none may start after it or run
    with a timeout past it."""

    def __init__(self, clock, deadline, replies, send_delay=0):
        self.clock, self.deadline = clock, deadline
        self.replies = list(replies)
        self.send_delay = send_delay
        self.timeout = None
        self.violations = []
        self.closed = False

    def check(self, op, timeout):
        left = self.deadline - self.clock.now
        if left <= 0:
            self.violations.append(f"{op} at {-left:.2f} s past the deadline")
        elif timeout is None or timeout > left + 1e-9:
            self.violations.append(f"{op} with timeout {timeout} and {left:.2f} s left")

    def connect(self, address, timeout):
        self.check("connect", timeout)
        self.timeout = timeout
        return self

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.check("sendall", self.timeout)
        if self.send_delay > self.timeout:
            self.clock.now += self.timeout
            raise socket.timeout("timed out")
        self.clock.now += self.send_delay

    def recv(self, n):
        self.check("recv", self.timeout)
        delay, data = self.replies.pop(0)
        if delay > self.timeout:
            self.clock.now += self.timeout
            self.replies.insert(0, (delay - self.timeout, data))
            raise socket.timeout("timed out")
        self.clock.now += delay
        return data

    def close(self):
        self.closed = True


class DeadlineTests(unittest.TestCase):
    def ping(self, replies):
        clock = Clock()
        sock = ScriptedSocket(clock, clock.now + stand.PING_TIMEOUT, replies)
        with mock.patch.object(stand, "time", types.SimpleNamespace(time=clock.time)), \
                mock.patch.object(stand.socket, "create_connection", sock.connect):
            ms = stand.ping()
        self.assertTrue(sock.closed)
        return ms, sock.violations

    def test_a_pong_after_the_deadline_is_a_failure(self):
        ms, violations = self.ping([(0, SOCKS_METHOD_REPLY), (0, SOCKS_CONNECT_REPLY), (0.05, PONG)])
        self.assertAlmostEqual(ms, 50.0)
        self.assertEqual(violations, [])

        # The headers and "p" come at 9.99 s, the rest trickles in by 10.11 s.
        ms, violations = self.ping([(0, SOCKS_METHOD_REPLY), (0, SOCKS_CONNECT_REPLY),
                                    (9.99, PONG[:-3]), (0.04, b"o"), (0.04, b"n"), (0.04, b"g")])
        self.assertIsNone(ms, "a request over the deadline must count as failed")
        self.assertEqual(violations, [])

    def test_every_send_and_receive_gets_only_the_time_left(self):
        # Each step is slow but the whole request ends at 9.5 s, in time.
        ms, violations = self.ping([(3, SOCKS_METHOD_REPLY), (3, SOCKS_CONNECT_REPLY), (3.5, PONG)])
        self.assertEqual(violations, [])
        self.assertAlmostEqual(ms, 9500.0)

    def test_an_upload_sends_its_request_with_only_the_time_left(self):
        clock = Clock()
        deadline = clock.now + 2.1
        sock = ScriptedSocket(clock, deadline, [], send_delay=1.0)
        sock.timeout = 9.0  # left by the SOCKS handshake, which has a deadline of its own
        result = {}
        with mock.patch.object(stand, "time", types.SimpleNamespace(time=clock.time)), \
                mock.patch.object(stand, "socks", return_value=sock):
            stand.upload(deadline, result)
        self.assertEqual(sock.violations, [])
        self.assertEqual(result, {"sent": 32768, "end": "deadline"})
        self.assertTrue(sock.closed)


if __name__ == "__main__":
    unittest.main()
