"""Tests for stand.py that need no root, network or real processes: the
clock, sockets and subprocesses are fakes.

  cd testing/xhttpflow/slowreader && python3 -B -m unittest test_stand
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
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
    than the timeout in effect times out, as a real one does. A reply may
    carry a third number, the time the caller then takes to run again. Every
    operation is checked against the request's deadline: none may start after
    it or run with a timeout past it."""

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
        delay, data, *resumed = self.replies.pop(0)
        if delay > self.timeout:
            self.clock.now += self.timeout
            self.replies.insert(0, (delay - self.timeout, data, *resumed))
            raise socket.timeout("timed out")
        self.clock.now += delay + sum(resumed)
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

        # The whole answer is in at 9.99 s, but ping runs again only at 10.01 s.
        ms, violations = self.ping([(0, SOCKS_METHOD_REPLY), (0, SOCKS_CONNECT_REPLY), (9.99, PONG, 0.02)])
        self.assertIsNone(ms, "an answer read after the deadline must count as failed")
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


VALID_RUN = {"p50": 53.0, "p95": 529.0, "pings": 30, "pings_failed": 0, "rss_mb": 39.8, "upload_mb": 24.0}


class ComparisonStatusTests(unittest.TestCase):
    def compare(self, before, after):
        out = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory())) / "runs.jsonl"
        args = types.SimpleNamespace(server=["before=/before", "after=/after"], runs=len(before), out=str(out))
        runs = {"/before": iter(before), "/after": iter(after)}
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(stand, "one_run", lambda binary, *_: next(runs[binary])), \
                mock.patch.object(stand.signal, "signal"), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = stand.inside(args)
        return code, stdout.getvalue(), [json.loads(line) for line in out.read_text().splitlines()]

    def test_one_invalid_run_fails_the_comparison_and_keeps_its_table(self):
        code, table, records = self.compare([VALID_RUN] * 36, [VALID_RUN] * 36)
        self.assertEqual(code, 0)
        self.assertIn("| Valid runs | 36 of 36 | 36 of 36 |", table)

        invalid = {"invalid": "Xray exited during the run"}
        code, table, records = self.compare([VALID_RUN] * 36, [VALID_RUN] * 35 + [invalid])
        self.assertEqual(code, 1, "a comparison with an invalid run is incomplete")
        self.assertIn("| Valid runs | 36 of 36 | 35 of 36 |", table)
        self.assertIn("| Requests failed or over 10 s | 0 of 1080 | 0 of 1050 |", table)
        self.assertEqual(len(records), 72)
        self.assertIn({"server": "after", **invalid}, records)


class WaitedForever(Exception):
    """Stands in for a wait with no deadline on a child that never exits."""


class FakeChild:
    """A child process. With exit_code None it runs until killed and ignores
    SIGTERM, as a stuck one would; otherwise it has exited with exit_code."""

    def __init__(self, name, events, exit_code):
        self.name, self.events = name, events
        self.returncode = exit_code
        self.pid = 4242

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.events.append((self.name, "wait", timeout))
        if self.returncode is None:
            if timeout is None:
                raise WaitedForever(self.name)
            raise subprocess.TimeoutExpired(self.name, timeout)
        return self.returncode

    def terminate(self):
        self.events.append((self.name, "terminate"))

    def kill(self):
        self.events.append((self.name, "kill"))
        self.returncode = -9


class FakeHost:
    """What outer() starts and runs on the host. The origin runs until it is
    killed; the measuring child exits with inside_exit, or never if None. The
    ip commands listed in failing exit with status 1."""

    def __init__(self, inside_exit=0, origin_stderr=b"", failing=()):
        self.inside_exit, self.origin_stderr, self.failing = inside_exit, origin_stderr, failing
        self.events = []
        self.popen_kwargs = {}

    def popen(self, argv, **kwargs):
        name = "inside" if "--inside" in argv else "origin"
        self.popen_kwargs[name] = kwargs
        if name == "origin" and self.origin_stderr and hasattr(kwargs.get("stderr"), "fileno"):
            os.write(kwargs["stderr"].fileno(), self.origin_stderr)
        return FakeChild(name, self.events, self.inside_exit if name == "inside" else None)

    def run(self, cmd, **kwargs):
        line = cmd if isinstance(cmd, str) else " ".join(cmd)
        self.events.append(("run", line))
        if line in self.failing:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr=f"{line}: Device or resource busy\n")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def teardown(self):
        """Who was stopped or removed after the first wait for the measuring
        child, in order: inside, origin, cli, srv, work."""
        first = next(i for i, e in enumerate(self.events) if e[:2] == ("inside", "wait"))
        stages = []
        for event in self.events[first + 1:]:
            if event[0] == "run":
                stage = event[1].rsplit("-", 1)[1]
            elif event[0] == "rmtree":
                stage = "work"
            else:
                stage = event[0]
            if not stages or stages[-1] != stage:
                stages.append(stage)
        return stages


class OuterTests(unittest.TestCase):
    RUNS = 36

    def outer(self, host):
        """Runs outer() against host; returns its exit code or the exception
        it raised, what it wrote to stderr, and its temporary directory."""
        args = types.SimpleNamespace(server=["before=/before", "after=/after"], runs=self.RUNS,
                                     origin="/origin", client="/client", out="runs.jsonl")
        real_mkdtemp, real_rmtree = tempfile.mkdtemp, shutil.rmtree
        work = []

        def mkdtemp(**kwargs):
            work.append(real_mkdtemp(**kwargs))
            self.addCleanup(real_rmtree, work[0], ignore_errors=True)
            return work[0]

        def rmtree(path, **kwargs):
            host.events.append(("rmtree", path))
            real_rmtree(path, **kwargs)

        stderr = io.StringIO()
        with mock.patch.object(stand.os, "geteuid", return_value=0), \
                mock.patch.object(stand.signal, "signal"), \
                mock.patch.object(stand, "reality_keys", return_value=("private", "public")), \
                mock.patch.object(stand.subprocess, "Popen", host.popen), \
                mock.patch.object(stand.subprocess, "run", host.run), \
                mock.patch.object(stand.tempfile, "mkdtemp", mkdtemp), \
                mock.patch.object(stand.shutil, "rmtree", rmtree), \
                contextlib.redirect_stderr(stderr):
            try:
                result = stand.outer(args)
            except Exception as e:
                result = e
        return result, stderr.getvalue(), work[0]

    def test_a_stuck_measurement_is_stopped_at_its_deadline_and_torn_down(self):
        host = FakeHost(inside_exit=None)
        result, stderr, work = self.outer(host)
        if isinstance(result, WaitedForever):
            self.fail("the parent waited for the measuring child with no deadline")
        self.assertNotEqual(result, 0)
        self.assertIn("did not finish", stderr)

        limit = host.events[[e[:2] for e in host.events].index(("inside", "wait"))][2]
        self.assertIsNotNone(limit)
        self.assertGreaterEqual(limit, 2 * self.RUNS * stand.DURATION, "the deadline must leave room for every run")
        self.assertLess(limit, 24 * 3600)

        self.assertEqual(host.teardown(), ["inside", "origin", "cli", "srv", "work"])
        self.assertIn(("inside", "terminate"), host.events)
        self.assertFalse(os.path.exists(work))

    def test_a_namespace_that_cannot_be_removed_is_reported_and_the_rest_removed(self):
        cli = f"xslow-{os.getpid()}-cli"
        host = FakeHost(failing=[f"ip netns del {cli}"], origin_stderr=b"origin diagnostic\n")
        result, stderr, work = self.outer(host)
        self.assertIsInstance(result, Exception, "a failed cleanup must not look like success")
        self.assertIn(cli, str(result))
        self.assertIn("Device or resource busy", str(result))
        self.assertIn("origin diagnostic", stderr, "the stand failed, so origin's stderr must be shown")
        self.assertEqual(host.teardown(), ["inside", "origin", "cli", "srv", "work"])
        self.assertIn(("run", f"ip netns del xslow-{os.getpid()}-srv"), host.events)
        self.assertFalse(os.path.exists(work))

    def test_origin_errors_are_kept_and_shown_when_the_comparison_fails(self):
        panic = "panic: listen tcp 127.0.0.1:18000: bind: address already in use"
        host = FakeHost(inside_exit=1, origin_stderr=panic.encode() + b"\n")
        result, stderr, work = self.outer(host)
        self.assertEqual(result, 1)
        self.assertIn(panic, stderr, "origin's stderr must be shown when the comparison fails")
        self.assertTrue(host.popen_kwargs["origin"]["stderr"].name.startswith(work + os.sep))

        host = FakeHost(inside_exit=0, origin_stderr=panic.encode() + b"\n")
        result, stderr, work = self.outer(host)
        self.assertEqual(result, 0)
        self.assertNotIn(panic, stderr)


class RemoveNamespaceTests(unittest.TestCase):
    def remove(self, results):
        calls = []

        def run(cmd, **kwargs):
            calls.append(" ".join(cmd))
            return results[cmd[2]]

        with mock.patch.object(stand.subprocess, "run", run), mock.patch.object(stand.os, "kill") as kill:
            try:
                stand.remove_namespace("xslow-1-cli")
                raised = None
            except Exception as e:
                raised = e
        return raised, calls, kill.call_args_list

    def test_failed_listing_and_deletion_are_reported(self):
        raised, calls, kills = self.remove({
            "pids": subprocess.CompletedProcess([], 0, stdout="11\n12\n", stderr=""),
            "del": subprocess.CompletedProcess([], 0, stdout="", stderr="")})
        self.assertIsNone(raised)
        self.assertEqual(kills, [mock.call(11, stand.signal.SIGKILL), mock.call(12, stand.signal.SIGKILL)])

        raised, calls, kills = self.remove({
            "pids": subprocess.CompletedProcess([], 1, stdout="", stderr="Cannot open network namespace\n"),
            "del": subprocess.CompletedProcess([], 1, stdout="", stderr="Device or resource busy\n")})
        self.assertIsNotNone(raised, "a failed cleanup must be reported")
        self.assertIn("xslow-1-cli", str(raised))
        self.assertIn("Cannot open network namespace", str(raised))
        self.assertIn("Device or resource busy", str(raised))
        self.assertEqual(calls, ["ip netns pids xslow-1-cli", "ip netns del xslow-1-cli"],
                         "deletion is still tried when listing fails")


if __name__ == "__main__":
    unittest.main()
