"""Tests for freshstart.py that need no root, network or real processes: the
clock, sockets and subprocesses are fakes.

  cd testing/xhttpflow/slowreader && python3 -B -m unittest test_freshstart
"""
import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import freshstart
import stand
from test_stand import SOCKS_CONNECT_REPLY, SOCKS_METHOD_REPLY, Clock, ScriptedSocket

SS_ONE_CONNECTION = ("cubic wscale:7,7 rto:252 rtt:50.1/0.2 mss:1448 cwnd:236 ssthresh:129 "
                     "bytes_sent:31000000 rcv_ssthresh:64076 minrtt:50.02\n")
SS_IN_SLOW_START = "cubic wscale:7,7 rto:252 rtt:50.1/0.2 mss:1448 cwnd:10 rcv_ssthresh:64076\n"


def ss_hangs(cmd, timeout=None, **kwargs):
    """An ss that does not finish. It can only be given up on by a caller
    that set a timeout: one run without would hang the stand, or count
    whenever ss did answer."""
    if timeout is None:
        raise AssertionError("ss was run without a timeout")
    raise subprocess.TimeoutExpired(cmd, timeout)


class RequestTests(unittest.TestCase):
    """request() and what it must not take for a transfer."""

    DEADLINE = 60.0

    def run_request(self, replies, call):
        clock = Clock()
        sock = ScriptedSocket(clock, clock.now + self.DEADLINE, replies)
        fake_time = types.SimpleNamespace(time=clock.time)
        with mock.patch.object(stand, "time", fake_time), mock.patch.object(freshstart, "time", fake_time), \
                mock.patch.object(stand.socket, "create_connection", sock.connect):
            try:
                result = call(clock.now + self.DEADLINE)
            except OSError as e:
                result = e
        self.assertTrue(sock.closed)
        self.assertEqual(sock.violations, [])
        return result

    def download(self, body, declared=None, last_delay=0.1, resumed=0.0):
        """A download of 1000 bytes answered with body, in two pieces."""
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % (len(body) if declared is None else declared)
        replies = [(0.01, SOCKS_METHOD_REPLY), (0.01, SOCKS_CONNECT_REPLY), (0.05, head + body[:400])]
        if body[400:]:
            replies.append((last_delay, body[400:], resumed))
        return self.run_request(replies, lambda deadline: freshstart.fetch(1000, deadline))

    def test_a_whole_download_is_timed_to_its_last_byte(self):
        seconds = self.download(bytes(1000))
        self.assertAlmostEqual(seconds, 0.15, places=6,
                               msg="from the request to the last byte, the SOCKS handshake left out")

    def test_a_last_byte_after_the_deadline_is_no_download(self):
        # The last chunk is read in time and the reader runs again only after
        # the deadline: the elapsed time would be a start of over a minute.
        result = self.download(bytes(1000), resumed=self.DEADLINE)
        self.assertIsInstance(result, OSError)
        self.assertIn("after the deadline", str(result))

    def test_a_body_of_another_length_is_no_download(self):
        for body, declared in ((b"", 0), (bytes(500), 500)):
            with self.subTest(declared=declared):
                result = self.download(body, declared)
                self.assertIsInstance(result, OSError, "a 200 with the wrong length was timed as a start")
                self.assertIn(f"{declared} bytes, not the 1000 asked for", str(result))

    def test_a_download_that_ends_early_is_no_download(self):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"
        replies = [(0.01, SOCKS_METHOD_REPLY), (0.01, SOCKS_CONNECT_REPLY), (0.05, head + bytes(400)), (0.1, b"")]
        result = self.run_request(replies, lambda deadline: freshstart.fetch(1000, deadline))
        self.assertIsInstance(result, OSError)
        self.assertIn("600 bytes to come", str(result))

    def upload(self, answer):
        head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(answer)
        return self.run_request([(0.01, SOCKS_METHOD_REPLY), (0.01, SOCKS_CONNECT_REPLY), (0.05, head + answer)],
                                lambda deadline: freshstart.send(70000, deadline))

    def test_an_upload_the_origin_read_whole_is_one(self):
        self.assertAlmostEqual(self.upload(b"70000"), 0.05, places=6)

    def test_an_upload_the_origin_counted_short_is_none(self):
        result = self.upload(b"65536")
        self.assertIsInstance(result, OSError)
        self.assertIn("not b'70000'", str(result))


class ClientConfigTests(unittest.TestCase):
    """--client-h2flow reaches the client's config, and only when given."""

    def extra(self, h2flow):
        config = stand.client_config("public", h2flow)
        return config["outbounds"][0]["streamSettings"]["xhttpSettings"]["extra"]

    def test_a_client_gets_no_governor_unless_asked(self):
        self.assertEqual(self.extra(None), {"xmux": stand.XMUX},
                         "the stands measure a server against a client as it comes")

    def test_the_clients_h2flow_object_is_passed_as_given(self):
        self.assertEqual(self.extra({"enabled": True}), {"xmux": stand.XMUX, "h2Flow": {"enabled": True}})
        self.assertEqual(self.extra({}), {"xmux": stand.XMUX, "h2Flow": {}}, "an empty object is an object")


class TCPStateTests(unittest.TestCase):
    """tcp_state() must tell "no threshold" from "no measurement"."""

    def state(self, run):
        with mock.patch.object(freshstart.subprocess, "run", run):
            return freshstart.tcp_state("srv")

    def ss(self, returncode=0, stdout="", stderr=""):
        return lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

    def test_a_connection_past_slow_start_has_a_threshold_and_a_window(self):
        self.assertEqual(self.state(self.ss(stdout=SS_ONE_CONNECTION)), ([129], [236]))

    def test_a_connection_in_slow_start_has_a_window_and_no_threshold(self):
        self.assertEqual(self.state(self.ss(stdout=SS_IN_SLOW_START)), ([], [10]))

    def test_a_failed_ss_is_no_measurement(self):
        with self.assertRaises(OSError) as raised:
            self.state(self.ss(returncode=1, stderr="Cannot open network namespace"))
        self.assertIn("status 1", str(raised.exception))
        self.assertIn("Cannot open network namespace", str(raised.exception))

    def test_an_ss_that_does_not_finish_is_no_measurement(self):
        with self.assertRaises(OSError):
            self.state(ss_hangs)

    def test_an_ss_that_shows_no_connection_is_no_measurement(self):
        with self.assertRaises(OSError):
            self.state(self.ss(stdout=""))


class RunTests(unittest.TestCase):
    """one_run() and inside() around a run that cannot be measured."""

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="freshstart-test-")
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.args = types.SimpleNamespace(before="nothing", srv_ns="srv", work=self.work, client="/client", starts=2,
                                          idle=0.0, bytes=1000, slow=0.7, runs=1, server=["a=/a"],
                                          out=os.path.join(self.work, "runs.jsonl"))

    def one_run(self, ss, fetch=lambda size, deadline: 0.5):
        alive = types.SimpleNamespace(poll=lambda: None)
        with mock.patch.object(freshstart.stand, "start_xray", lambda *a: (alive, alive)), \
                mock.patch.object(freshstart.stand, "ping", lambda *a: 1.0), \
                mock.patch.object(freshstart, "fetch", fetch), \
                mock.patch.object(freshstart.subprocess, "run", ss), \
                mock.patch.object(freshstart.time, "sleep", lambda s: None):
            return freshstart.one_run("/a", self.args, "a")

    def test_a_run_gives_its_starts_and_the_servers_tcp_state(self):
        ss = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=SS_ONE_CONNECTION, stderr="")
        self.assertEqual(self.one_run(ss), {"starts": [0.5, 0.5], "ssthresh": [129], "cwnd": [236]})

    def test_a_run_whose_ss_fails_is_invalid(self):
        failures = {
            "status 1": lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no namespace"),
            "no connection": lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""),
        }
        failures["timeout"] = ss_hangs
        for name, ss in failures.items():
            with self.subTest(name):
                r = self.one_run(ss)
                self.assertIn("invalid", r, "a failed ss must not read as a connection without a threshold")
                self.assertIn("TCP state could not be read", r["invalid"])
                self.assertNotIn("starts", r)

    def test_a_run_whose_download_fails_is_invalid(self):
        def fails(size, deadline):
            raise OSError("a body of 0 bytes, not the 1000 asked for")

        ss = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=SS_ONE_CONNECTION, stderr="")
        r = self.one_run(ss, fails)
        self.assertIn("a timed download failed", r["invalid"])

    def inside(self, one_run):
        for who in ("server", "client"):
            with open(os.path.join(self.work, f"{who}.log"), "w") as f:
                f.write(f"{who} diagnostic\n")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(freshstart, "one_run", one_run), mock.patch.object(freshstart.signal, "signal"), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                result = freshstart.inside(self.args)
            except Exception as e:
                result = e
        return result, out.getvalue(), err.getvalue()

    def test_an_invalid_run_shows_what_xray_wrote_and_fails_the_stand(self):
        result, out, err = self.inside(lambda *a: {"invalid": "the tunnel did not come up"})
        self.assertEqual(result, 1)
        self.assertIn("INVALID, the tunnel did not come up", out)
        self.assertIn("server diagnostic", err)
        self.assertIn("client diagnostic", err)

    def test_a_run_that_raises_shows_what_xray_wrote_before_the_directory_goes(self):
        def raises(*a):
            raise FileNotFoundError("/client")

        result, _, err = self.inside(raises)
        self.assertIsInstance(result, FileNotFoundError)
        self.assertIn("server diagnostic", err,
                      "the server had started and its output would go with the work directory")
        self.assertIn("client diagnostic", err)


if __name__ == "__main__":
    unittest.main()
