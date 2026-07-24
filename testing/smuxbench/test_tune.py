import copy
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

import tune


class CandidateTests(unittest.TestCase):
    def test_generate_candidates_includes_disabled_and_grid(self):
        candidates = tune.generate_candidates(
            min_streams=[1, 4],
            max_connections=[1, 2],
            padding=[False, True],
            include_disabled=True,
            only_tcp=True,
        )
        self.assertEqual(candidates[0].candidate_id, "smux-off")
        self.assertFalse(candidates[0].enabled)
        self.assertEqual(len(candidates), 9)
        self.assertEqual(len({candidate.candidate_id for candidate in candidates}), 9)

    def test_patch_config_selects_tag_without_mutating_input(self):
        base = {
            "outbounds": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "proxy", "protocol": "vless", "settings": {"secret": "kept"}},
            ]
        }
        original = copy.deepcopy(base)
        candidate = tune.Candidate(True, 1, 4, False, True)
        patched = tune.patch_config(base, candidate, "proxy")
        self.assertEqual(base, original)
        self.assertNotIn("smux", patched["outbounds"][0])
        self.assertEqual(
            patched["outbounds"][1]["smux"],
            {
                "enabled": True,
                "protocol": "smux",
                "minStreams": 1,
                "maxConnections": 4,
                "padding": False,
                "onlyTcp": True,
            },
        )
        self.assertEqual(patched["outbounds"][1]["settings"]["secret"], "kept")

    def test_patch_config_rejects_unknown_tag(self):
        with self.assertRaisesRegex(ValueError, "outbound tag"):
            tune.patch_config({"outbounds": [{"tag": "proxy"}]}, tune.Candidate.disabled(), "missing")

    def test_parsers_and_addresses(self):
        self.assertEqual(tune.parse_int_list("4,1,4"), [1, 4])
        self.assertEqual(tune.parse_bool_list("true,false,true"), [True, False])
        self.assertEqual(tune.parse_modes("download,bidi"), ["download", "bidirectional"])
        self.assertEqual(tune.split_address("127.0.0.1:1080"), ("127.0.0.1", "1080"))
        self.assertEqual(tune.split_address("[::1]:1080"), ("::1", "1080"))
        with self.assertRaises(ValueError):
            tune.split_address("missing-port")


class MetricsTests(unittest.TestCase):
    def test_aggregate_benchmark_uses_median_and_variation(self):
        document = {
            "mode": "download",
            "parallel": 4,
            "rounds": [
                {"aggregate_mbps": 100.0, "connect_ms": {"p95": 10.0}, "errors": []},
                {"aggregate_mbps": 120.0, "connect_ms": {"p95": 12.0}, "errors": []},
                {"aggregate_mbps": 110.0, "connect_ms": {"p95": 11.0}, "errors": []},
            ],
        }
        metrics = tune.aggregate_benchmark(document)
        self.assertEqual(metrics.throughput_mbps, 110.0)
        self.assertEqual(metrics.connect_p95_ms, 11.0)
        self.assertGreater(metrics.throughput_cv, 0)

    def test_rank_candidates_uses_geometric_ratio_and_stability(self):
        baseline = tune.CandidateResult(
            tune.Candidate.disabled(),
            scenarios={
                "download-p4": tune.ScenarioMetrics("download", 4, 100.0, 10.0, 0.02),
                "upload-p4": tune.ScenarioMetrics("upload", 4, 100.0, 10.0, 0.02),
            },
        )
        fast = tune.CandidateResult(
            tune.Candidate(True, 1, 4, False, True),
            scenarios={
                "download-p4": tune.ScenarioMetrics("download", 4, 150.0, 11.0, 0.03),
                "upload-p4": tune.ScenarioMetrics("upload", 4, 140.0, 11.0, 0.03),
            },
        )
        unstable = tune.CandidateResult(
            tune.Candidate(True, 4, 4, True, True),
            scenarios={
                "download-p4": tune.ScenarioMetrics("download", 4, 155.0, 20.0, 0.50),
                "upload-p4": tune.ScenarioMetrics("upload", 4, 145.0, 20.0, 0.50),
            },
        )
        ranked = tune.rank_candidates([baseline, unstable, fast])
        self.assertEqual(ranked[0].candidate.candidate_id, fast.candidate.candidate_id)
        self.assertGreater(ranked[0].score, ranked[1].score)

    def test_geometric_mean_preserves_zero_throughput(self):
        self.assertEqual(tune.geometric_mean([100.0, 0.0]), 0.0)

    def test_rank_candidates_rejects_failed_required_baseline(self):
        failed_baseline = tune.CandidateResult(
            tune.Candidate.disabled(),
            scenarios={},
            error="benchmark failed",
        )
        candidate = tune.CandidateResult(
            tune.Candidate(True, 1, 4, False, True),
            scenarios={
                "download-p1": tune.ScenarioMetrics("download", 1, 100.0, 2.0, 0.01),
            },
        )

        with self.assertRaisesRegex(ValueError, "SMUX-disabled baseline"):
            tune.rank_candidates([failed_baseline, candidate], require_baseline=True)

    def test_counter_delta_preserves_positive_changes(self):
        self.assertEqual(
            tune.counter_delta({"RetransSegs": 10, "OutRsts": 4}, {"RetransSegs": 13, "OutRsts": 4}),
            {"RetransSegs": 3, "OutRsts": 0},
        )

    def test_read_interface_counters_uses_carrier_changes_from_interface_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            interface = root / "eth0"
            statistics_root = interface / "statistics"
            statistics_root.mkdir(parents=True)
            (statistics_root / "rx_errors").write_text("2\n", encoding="ascii")
            (interface / "carrier_changes").write_text("3\n", encoding="ascii")

            self.assertEqual(
                tune.read_interface_counters("eth0", root),
                {"rx_errors": 2, "carrier_changes": 3},
            )


class OrchestrationTests(unittest.TestCase):
    def test_run_candidate_collects_metrics_and_raw_result(self):
        document = {
            "mode": "download",
            "parallel": 1,
            "rounds": [
                {"aggregate_mbps": 123.0, "connect_ms": {"p95": 3.0}, "errors": []},
            ],
        }
        process = FakeProcess()
        sampler = FakeSampler(process)
        args = types.SimpleNamespace(
            outbound_tag="proxy",
            interface="eth0",
            xray_bin="/fake/xray",
            xray_workdir=None,
            socks="127.0.0.1:1080",
            startup_timeout=1.0,
            modes=["download"],
            parallel=[1],
            bench_bin="/fake/smuxbench",
            target="127.0.0.1:5201",
            duration="1s",
            warmup="0s",
            rounds=1,
            block_size=8192,
            connect_timeout="1s",
            benchmark_timeout=5.0,
        )
        base = {"outbounds": [{"tag": "proxy", "protocol": "vless"}]}
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            temporary = output / "temporary"
            temporary.mkdir()
            with (
                mock.patch.object(tune.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    tune.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(
                        returncode=0, stdout=json.dumps(document), stderr=""
                    ),
                ),
                mock.patch.object(tune, "wait_for_tcp"),
                mock.patch.object(tune, "ProcessSampler", return_value=sampler),
                mock.patch.object(
                    tune,
                    "read_linux_tcp_counters",
                    side_effect=[{"RetransSegs": 10}, {"RetransSegs": 12}],
                ),
                mock.patch.object(
                    tune,
                    "read_interface_counters",
                    side_effect=[{"rx_errors": 1}, {"rx_errors": 1}],
                ),
            ):
                result = tune.run_candidate(
                    args,
                    base,
                    tune.Candidate(True, 1, 4, False, True),
                    output,
                    temporary,
                )
            self.assertIsNone(result.error)
            self.assertEqual(result.scenarios["download-p1"].throughput_mbps, 123.0)
            self.assertEqual(result.tcp_delta["RetransSegs"], 2)
            self.assertEqual(result.cpu_peak_percent, 80.0)
            self.assertTrue(
                (output / "raw" / result.candidate.candidate_id / "download-p1.json").is_file()
            )

    def test_run_tuner_writes_ranked_artifacts_and_private_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            xray = root / "xray"
            benchmark = root / "smuxbench"
            base_path = root / "client.json"
            xray.write_bytes(b"xray")
            benchmark.write_bytes(b"bench")
            base_path.write_text(
                json.dumps({"outbounds": [{"tag": "proxy", "protocol": "vless"}]}),
                encoding="utf-8",
            )
            output = root / "results"
            args = tune.create_parser().parse_args(
                [
                    "--xray-bin", str(xray),
                    "--bench-bin", str(benchmark),
                    "--base-config", str(base_path),
                    "--outbound-tag", "proxy",
                    "--target", "127.0.0.1:5201",
                    "--socks", "127.0.0.1:1080",
                    "--output", str(output),
                    "--min-streams", "1",
                    "--max-connections", "4",
                    "--padding", "false",
                    "--parallel", "1",
                    "--modes", "download",
                ]
            )

            def fake_candidate(_args, _base, candidate, _output, _temporary):
                speed = 120.0 if candidate.enabled else 100.0
                return tune.CandidateResult(
                    candidate,
                    {"download-p1": tune.ScenarioMetrics("download", 1, speed, 2.0, 0.01)},
                )

            with mock.patch.object(tune, "run_candidate", side_effect=fake_candidate):
                result_path = tune.run_tuner(args)
            self.assertEqual(result_path, output.resolve())
            self.assertTrue((output / "REPORT.md").is_file())
            self.assertTrue((output / "summary.csv").is_file())
            best = json.loads((output / "best-candidate.json").read_text(encoding="utf-8"))
            self.assertTrue(best["candidate"]["enabled"])
            self.assertEqual(os.stat(output / "best-config.json").st_mode & 0o777, 0o600)

    def test_run_tuner_fails_when_no_candidate_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            xray = root / "xray"
            benchmark = root / "smuxbench"
            base_path = root / "client.json"
            xray.write_bytes(b"xray")
            benchmark.write_bytes(b"bench")
            base_path.write_text(
                json.dumps({"outbounds": [{"tag": "proxy", "protocol": "vless"}]}),
                encoding="utf-8",
            )
            args = tune.create_parser().parse_args(
                [
                    "--xray-bin", str(xray),
                    "--bench-bin", str(benchmark),
                    "--base-config", str(base_path),
                    "--target", "127.0.0.1:5201",
                    "--socks", "127.0.0.1:1080",
                    "--output", str(root / "results"),
                    "--min-streams", "1",
                    "--max-connections", "4",
                    "--padding", "false",
                    "--parallel", "1",
                    "--modes", "download",
                    "--no-disabled",
                ]
            )

            def failed_candidate(_args, _base, candidate, _output, _temporary):
                return tune.CandidateResult(candidate, scenarios={}, error="benchmark failed")

            with (
                mock.patch.object(tune, "run_candidate", side_effect=failed_candidate),
                self.assertRaisesRegex(ValueError, "no candidate completed successfully"),
            ):
                tune.run_tuner(args)


class FakeProcess:
    def __init__(self):
        self.pid = os.getpid()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class FakeSampler:
    def __init__(self, process):
        self.process = process

    def start(self):
        pass

    def stop(self):
        pass

    def summary(self):
        return 80.0, 50.0, 4096, 8, 16


if __name__ == "__main__":
    unittest.main()
