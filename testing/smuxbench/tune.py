#!/usr/bin/env python3
"""Benchmark and tune Xray SMUX pool settings through a local SOCKS5 inbound."""

from __future__ import annotations

import argparse
import copy
import csv
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import platform
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable, Optional


@dataclasses.dataclass(frozen=True)
class Candidate:
    enabled: bool
    min_streams: int
    max_connections: int
    padding: bool
    only_tcp: bool

    @classmethod
    def disabled(cls) -> "Candidate":
        return cls(False, 0, 0, False, True)

    @property
    def candidate_id(self) -> str:
        if not self.enabled:
            return "smux-off"
        return (
            f"smux-min{self.min_streams}-max{self.max_connections}"
            f"-pad{int(self.padding)}-tcp{int(self.only_tcp)}"
        )

    def public_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self) | {"candidate_id": self.candidate_id}


@dataclasses.dataclass
class ScenarioMetrics:
    mode: str
    parallel: int
    throughput_mbps: float
    connect_p95_ms: float
    throughput_cv: float
    rounds: int = 0
    errors: int = 0


@dataclasses.dataclass
class CandidateResult:
    candidate: Candidate
    scenarios: dict[str, ScenarioMetrics]
    cpu_peak_percent: float = 0.0
    cpu_mean_percent: float = 0.0
    rss_peak_kib: int = 0
    threads_peak: int = 0
    file_descriptors_peak: int = 0
    tcp_delta: dict[str, int] = dataclasses.field(default_factory=dict)
    interface_delta: dict[str, int] = dataclasses.field(default_factory=dict)
    error: Optional[str] = None
    score: float = 0.0
    throughput_ratio: float = 0.0
    mean_cv: float = 0.0

    def serializable(self) -> dict[str, Any]:
        return {
            "candidate": self.candidate.public_dict(),
            "scenarios": {
                key: dataclasses.asdict(value) for key, value in sorted(self.scenarios.items())
            },
            "cpu_peak_percent": self.cpu_peak_percent,
            "cpu_mean_percent": self.cpu_mean_percent,
            "rss_peak_kib": self.rss_peak_kib,
            "threads_peak": self.threads_peak,
            "file_descriptors_peak": self.file_descriptors_peak,
            "tcp_delta": self.tcp_delta,
            "interface_delta": self.interface_delta,
            "error": self.error,
            "score": self.score,
            "throughput_ratio": self.throughput_ratio,
            "mean_cv": self.mean_cv,
        }


def parse_int_list(value: str) -> list[int]:
    try:
        values = [int(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid integer list {value!r}") from error
    if not values or any(item <= 0 for item in values):
        raise argparse.ArgumentTypeError("integer lists must contain positive values")
    return sorted(set(values))


def parse_bool_list(value: str) -> list[bool]:
    result: list[bool] = []
    for item in value.split(","):
        normalized = item.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            result.append(True)
        elif normalized in {"false", "0", "no", "off"}:
            result.append(False)
        elif normalized:
            raise argparse.ArgumentTypeError(f"invalid boolean {item!r}")
    if not result:
        raise argparse.ArgumentTypeError("boolean list must not be empty")
    return list(dict.fromkeys(result))


def parse_modes(value: str) -> list[str]:
    aliases = {"bidi": "bidirectional"}
    allowed = {"download", "upload", "bidirectional"}
    modes = []
    for item in value.split(","):
        mode = aliases.get(item.strip().lower(), item.strip().lower())
        if mode not in allowed:
            raise argparse.ArgumentTypeError(f"invalid mode {item!r}")
        if mode not in modes:
            modes.append(mode)
    if not modes:
        raise argparse.ArgumentTypeError("mode list must not be empty")
    return modes


def generate_candidates(
    min_streams: Iterable[int],
    max_connections: Iterable[int],
    padding: Iterable[bool],
    include_disabled: bool,
    only_tcp: bool,
) -> list[Candidate]:
    candidates: list[Candidate] = []
    if include_disabled:
        candidates.append(Candidate.disabled())
    for minimum in min_streams:
        for maximum in max_connections:
            for padded in padding:
                candidates.append(Candidate(True, minimum, maximum, padded, only_tcp))
    return candidates


def patch_config(base: dict[str, Any], candidate: Candidate, outbound_tag: Optional[str]) -> dict[str, Any]:
    patched = copy.deepcopy(base)
    outbounds = patched.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("base config must contain a non-empty outbounds array")
    selected: Optional[dict[str, Any]] = None
    if outbound_tag:
        for outbound in outbounds:
            if isinstance(outbound, dict) and outbound.get("tag") == outbound_tag:
                selected = outbound
                break
        if selected is None:
            raise ValueError(f"outbound tag {outbound_tag!r} was not found")
    else:
        if not isinstance(outbounds[0], dict):
            raise ValueError("first outbound is not an object")
        selected = outbounds[0]
    if candidate.enabled:
        selected["smux"] = {
            "enabled": True,
            "protocol": "smux",
            "minStreams": candidate.min_streams,
            "maxConnections": candidate.max_connections,
            "padding": candidate.padding,
            "onlyTcp": candidate.only_tcp,
        }
    else:
        selected["smux"] = {"enabled": False}
    return patched


def aggregate_benchmark(document: dict[str, Any]) -> ScenarioMetrics:
    rounds = document.get("rounds")
    if not isinstance(rounds, list) or not rounds:
        raise ValueError("benchmark result has no rounds")
    throughputs: list[float] = []
    latencies: list[float] = []
    errors = 0
    for round_result in rounds:
        if not isinstance(round_result, dict):
            raise ValueError("benchmark round is not an object")
        round_errors = round_result.get("errors") or []
        errors += len(round_errors)
        if round_errors:
            continue
        throughputs.append(float(round_result["aggregate_mbps"]))
        latencies.append(float(round_result["connect_ms"]["p95"]))
    if not throughputs:
        raise ValueError("all benchmark rounds failed")
    mean = statistics.fmean(throughputs)
    variation = statistics.pstdev(throughputs) / mean if len(throughputs) > 1 and mean > 0 else 0.0
    return ScenarioMetrics(
        mode=str(document["mode"]),
        parallel=int(document["parallel"]),
        throughput_mbps=statistics.median(throughputs),
        connect_p95_ms=statistics.median(latencies),
        throughput_cv=variation,
        rounds=len(throughputs),
        errors=errors,
    )


def scenario_key(mode: str, parallel: int) -> str:
    return f"{mode}-p{parallel}"


def geometric_mean(values: Iterable[float]) -> float:
    numbers = list(values)
    if not numbers or any(value == 0 for value in numbers):
        return 0.0
    if any(value < 0 or not math.isfinite(value) for value in numbers):
        raise ValueError("geometric mean requires finite non-negative values")
    return math.exp(statistics.fmean(math.log(value) for value in numbers))


def rank_candidates(
    results: list[CandidateResult],
    require_baseline: bool = True,
) -> list[CandidateResult]:
    disabled_result = next(
        (result for result in results if not result.candidate.enabled),
        None,
    )
    if require_baseline and (
        disabled_result is None
        or disabled_result.error is not None
        or not disabled_result.scenarios
    ):
        raise ValueError("SMUX-disabled baseline did not complete successfully")
    baseline = (
        disabled_result
        if disabled_result is not None
        and disabled_result.error is None
        and disabled_result.scenarios
        else None
    )
    for result in results:
        if result.error or not result.scenarios:
            result.score = 0.0
            continue
        result.mean_cv = statistics.fmean(
            metric.throughput_cv for metric in result.scenarios.values()
        )
        if baseline is not None:
            common = sorted(set(result.scenarios) & set(baseline.scenarios))
            ratios = [
                result.scenarios[key].throughput_mbps
                / baseline.scenarios[key].throughput_mbps
                for key in common
                if baseline.scenarios[key].throughput_mbps > 0
            ]
            result.throughput_ratio = geometric_mean(ratios)
        else:
            result.throughput_ratio = geometric_mean(
                metric.throughput_mbps for metric in result.scenarios.values()
            )
        result.score = result.throughput_ratio / (1.0 + result.mean_cv)
    return sorted(
        results,
        key=lambda result: (
            result.error is None,
            result.score,
            -result.cpu_mean_percent,
            -result.rss_peak_kib,
        ),
        reverse=True,
    )


def counter_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {
        key: after.get(key, 0) - before.get(key, 0)
        for key in sorted(set(before) | set(after))
    }


def read_linux_tcp_counters() -> dict[str, int]:
    path = pathlib.Path("/proc/net/snmp")
    if not path.exists():
        return {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for index in range(len(lines) - 1):
        if lines[index].startswith("Tcp:") and lines[index + 1].startswith("Tcp:"):
            names = lines[index].split()[1:]
            values = lines[index + 1].split()[1:]
            parsed = {name: int(value) for name, value in zip(names, values)}
            return {
                key: parsed[key]
                for key in ("RetransSegs", "OutRsts", "InErrs")
                if key in parsed
            }
    return {}


INTERFACE_COUNTERS = (
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
    "rx_crc_errors",
    "tx_carrier_errors",
    "collisions",
    "carrier_changes",
)


def read_interface_counters(
    interface: Optional[str],
    sys_class_net: pathlib.Path = pathlib.Path("/sys/class/net"),
) -> dict[str, int]:
    if not interface:
        return {}
    interface_root = sys_class_net / interface
    statistics_root = interface_root / "statistics"
    if not interface_root.is_dir():
        return {}
    counters: dict[str, int] = {}
    for name in INTERFACE_COUNTERS:
        path = (
            interface_root / name
            if name == "carrier_changes"
            else statistics_root / name
        )
        if path.exists():
            counters[name] = int(path.read_text(encoding="ascii").strip())
    return counters


@dataclasses.dataclass
class ProcessSample:
    cpu_percent: float
    rss_kib: int
    threads: int
    file_descriptors: int


class ProcessSampler:
    def __init__(self, process: subprocess.Popen[str], interval: float = 0.25):
        self.process = process
        self.interval = interval
        self.samples: list[ProcessSample] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="xray-metrics", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(2.0, self.interval * 4))

    def _run(self) -> None:
        while not self._stop.is_set() and self.process.poll() is None:
            sample = sample_process(self.process.pid)
            if sample is not None:
                self.samples.append(sample)
            self._stop.wait(self.interval)

    def summary(self) -> tuple[float, float, int, int, int]:
        if not self.samples:
            return 0.0, 0.0, 0, 0, 0
        return (
            max(sample.cpu_percent for sample in self.samples),
            statistics.fmean(sample.cpu_percent for sample in self.samples),
            max(sample.rss_kib for sample in self.samples),
            max(sample.threads for sample in self.samples),
            max(sample.file_descriptors for sample in self.samples),
        )


def sample_process(pid: int) -> Optional[ProcessSample]:
    proc_root = pathlib.Path("/proc") / str(pid)
    if proc_root.is_dir():
        status: dict[str, str] = {}
        for line in (proc_root / "status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                status[key] = value.strip()
        rss = int(status.get("VmRSS", "0 kB").split()[0])
        threads = int(status.get("Threads", "0"))
        descriptors = len(list((proc_root / "fd").iterdir()))
        cpu = process_cpu_percent(pid)
        return ProcessSample(cpu, rss, threads, descriptors)
    try:
        completed = subprocess.run(
            ["ps", "-o", "%cpu=", "-o", "rss=", "-p", str(pid)],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        fields = completed.stdout.split()
        if len(fields) < 2:
            return None
        return ProcessSample(float(fields[0]), int(fields[1]), 0, 0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def process_cpu_percent(pid: int) -> float:
    try:
        completed = subprocess.run(
            ["ps", "-o", "%cpu=", "-p", str(pid)],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return float(completed.stdout.strip() or 0.0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0.0


def wait_for_tcp(address: str, process: subprocess.Popen[str], timeout: float) -> None:
    host, port_text = split_address(address)
    deadline = time.monotonic() + timeout
    last_error: Optional[OSError] = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Xray exited with status {process.returncode} before SOCKS readiness")
        try:
            with socket.create_connection((host, int(port_text)), timeout=0.25):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    raise TimeoutError(f"SOCKS address {address} did not open: {last_error}")


def split_address(address: str) -> tuple[str, str]:
    if address.startswith("["):
        host, separator, port = address[1:].partition("]:")
        if not separator:
            raise ValueError(f"invalid address {address!r}")
        return host, port
    host, separator, port = address.rpartition(":")
    if not separator or not host or not port:
        raise ValueError(f"invalid address {address!r}")
    return host, port


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_candidate(
    args: argparse.Namespace,
    base_config: dict[str, Any],
    candidate: Candidate,
    output_directory: pathlib.Path,
    temporary_directory: pathlib.Path,
) -> CandidateResult:
    print(f"[{candidate.candidate_id}] starting", flush=True)
    config = patch_config(base_config, candidate, args.outbound_tag)
    config_path = temporary_directory / f"{candidate.candidate_id}.json"
    write_json(config_path, config, mode=0o600)
    log_path = output_directory / "logs" / f"{candidate.candidate_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(log_path.parent, 0o700)
    log_descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    log_file = os.fdopen(log_descriptor, "w", encoding="utf-8")
    process: Optional[subprocess.Popen[str]] = None
    sampler: Optional[ProcessSampler] = None
    tcp_before = read_linux_tcp_counters()
    interface_before = read_interface_counters(args.interface)
    result = CandidateResult(candidate, scenarios={})
    try:
        process = subprocess.Popen(
            [args.xray_bin, "run", "-config", str(config_path)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=args.xray_workdir,
        )
        wait_for_tcp(args.socks, process, args.startup_timeout)
        sampler = ProcessSampler(process)
        sampler.start()
        for mode in args.modes:
            for parallel in args.parallel:
                key = scenario_key(mode, parallel)
                command = [
                    args.bench_bin,
                    "client",
                    "--target",
                    args.target,
                    "--proxy",
                    args.socks,
                    "--mode",
                    mode,
                    "--parallel",
                    str(parallel),
                    "--duration",
                    args.duration,
                    "--warmup",
                    args.warmup,
                    "--rounds",
                    str(args.rounds),
                    "--block-size",
                    str(args.block_size),
                    "--timeout",
                    args.connect_timeout,
                ]
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=args.benchmark_timeout,
                )
                if completed.returncode != 0:
                    raise RuntimeError(
                        f"benchmark {key} exited {completed.returncode}: {completed.stderr.strip()}"
                    )
                document = json.loads(completed.stdout)
                result.scenarios[key] = aggregate_benchmark(document)
                raw_path = output_directory / "raw" / candidate.candidate_id / f"{key}.json"
                write_json(raw_path, document)
                metrics = result.scenarios[key]
                print(
                    f"[{candidate.candidate_id}] {key}: "
                    f"{metrics.throughput_mbps:.2f} Mbps, cv={metrics.throughput_cv:.3f}",
                    flush=True,
                )
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as error:
        result.error = str(error)
        print(f"[{candidate.candidate_id}] failed: {error}", file=sys.stderr, flush=True)
    finally:
        if sampler is not None:
            sampler.stop()
            (
                result.cpu_peak_percent,
                result.cpu_mean_percent,
                result.rss_peak_kib,
                result.threads_peak,
                result.file_descriptors_peak,
            ) = sampler.summary()
        if process is not None:
            stop_process(process)
        log_file.close()
        result.tcp_delta = counter_delta(tcp_before, read_linux_tcp_counters())
        result.interface_delta = counter_delta(
            interface_before, read_interface_counters(args.interface)
        )
    return result


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: pathlib.Path, value: Any, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as destination:
        json.dump(value, destination, indent=2, sort_keys=True)
        destination.write("\n")
    os.chmod(temporary, mode)
    temporary.replace(path)


def write_summary_csv(path: pathlib.Path, ranked: list[CandidateResult]) -> None:
    scenario_names = sorted({key for result in ranked for key in result.scenarios})
    fields = [
        "rank",
        "candidate_id",
        "enabled",
        "min_streams",
        "max_connections",
        "padding",
        "score",
        "throughput_ratio",
        "mean_cv",
        "cpu_mean_percent",
        "cpu_peak_percent",
        "rss_peak_kib",
        "retransmits",
        "error",
    ] + [f"{name}_mbps" for name in scenario_names]
    with path.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for index, result in enumerate(ranked, 1):
            row: dict[str, Any] = {
                "rank": index,
                "candidate_id": result.candidate.candidate_id,
                "enabled": result.candidate.enabled,
                "min_streams": result.candidate.min_streams,
                "max_connections": result.candidate.max_connections,
                "padding": result.candidate.padding,
                "score": result.score,
                "throughput_ratio": result.throughput_ratio,
                "mean_cv": result.mean_cv,
                "cpu_mean_percent": result.cpu_mean_percent,
                "cpu_peak_percent": result.cpu_peak_percent,
                "rss_peak_kib": result.rss_peak_kib,
                "retransmits": result.tcp_delta.get("RetransSegs", 0),
                "error": result.error or "",
            }
            for name in scenario_names:
                metric = result.scenarios.get(name)
                row[f"{name}_mbps"] = metric.throughput_mbps if metric else ""
            writer.writerow(row)


def write_report(path: pathlib.Path, ranked: list[CandidateResult]) -> None:
    lines = [
        "# Xray SMUX tuning report",
        "",
        "Score is the geometric mean throughput ratio against SMUX-off, penalized by round-to-round variation.",
        "System-wide Linux TCP/interface deltas may include unrelated host traffic.",
        "",
        "| Rank | Candidate | Score | vs off | CV | CPU mean | RSS peak KiB | Retrans | Error |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for index, result in enumerate(ranked, 1):
        lines.append(
            f"| {index} | `{result.candidate.candidate_id}` | {result.score:.3f} | "
            f"{result.throughput_ratio:.3f} | {result.mean_cv:.3f} | "
            f"{result.cpu_mean_percent:.1f}% | {result.rss_peak_kib} | "
            f"{result.tcp_delta.get('RetransSegs', 0)} | {result.error or ''} |"
        )
    lines.extend(["", "## Scenario medians", ""])
    for result in ranked:
        lines.append(f"### {result.candidate.candidate_id}")
        lines.append("")
        if result.error:
            lines.extend([f"Failed: `{result.error}`", ""])
            continue
        lines.append("| Scenario | Throughput Mbps | Connect p95 ms | CV |")
        lines.append("| --- | ---: | ---: | ---: |")
        for key, metric in sorted(result.scenarios.items()):
            lines.append(
                f"| {key} | {metric.throughput_mbps:.2f} | "
                f"{metric.connect_p95_ms:.2f} | {metric.throughput_cv:.3f} |"
            )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xray-bin", required=True, help="Xray executable to restart per candidate")
    parser.add_argument("--bench-bin", required=True, help="compiled smuxbench executable")
    parser.add_argument("--base-config", required=True, help="client config containing the SOCKS inbound")
    parser.add_argument(
        "--xray-workdir",
        help="Xray working directory; defaults to the base config directory",
    )
    parser.add_argument("--outbound-tag", help="outbound whose smux block should be replaced; defaults to first")
    parser.add_argument("--target", required=True, help="remote smuxbench server host:port")
    parser.add_argument("--socks", required=True, help="local Xray SOCKS5 host:port")
    parser.add_argument("--output", required=True, help="new output directory")
    parser.add_argument("--min-streams", type=parse_int_list, default=parse_int_list("1,4,8"))
    parser.add_argument("--max-connections", type=parse_int_list, default=parse_int_list("1,2,4"))
    parser.add_argument("--padding", type=parse_bool_list, default=parse_bool_list("false,true"))
    parser.add_argument("--only-tcp", type=parse_bool_list, default=[True])
    parser.add_argument("--parallel", type=parse_int_list, default=parse_int_list("1,4,8"))
    parser.add_argument("--modes", type=parse_modes, default=parse_modes("download,upload"))
    parser.add_argument("--duration", default="5s")
    parser.add_argument("--warmup", default="1s")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--block-size", type=int, default=32 * 1024)
    parser.add_argument("--connect-timeout", default="10s")
    parser.add_argument("--startup-timeout", type=float, default=10.0)
    parser.add_argument("--benchmark-timeout", type=float, default=300.0)
    parser.add_argument("--interface", help="Linux interface for error/drop counter deltas")
    parser.add_argument("--seed", type=int, default=1, help="candidate order seed")
    parser.add_argument("--no-disabled", action="store_true", help="omit the SMUX-off baseline")
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    if args.rounds <= 0:
        raise ValueError("rounds must be positive")
    if args.block_size < 256 or args.block_size > 1024 * 1024:
        raise ValueError("block-size must be between 256 and 1048576")
    if len(args.only_tcp) != 1:
        raise ValueError("only-tcp accepts exactly one boolean value")
    split_address(args.target)
    split_address(args.socks)
    for executable in (args.xray_bin, args.bench_bin):
        if not pathlib.Path(executable).is_file():
            raise ValueError(f"executable not found: {executable}")
    if not pathlib.Path(args.base_config).is_file():
        raise ValueError(f"base config not found: {args.base_config}")
    if args.xray_workdir and not pathlib.Path(args.xray_workdir).is_dir():
        raise ValueError(f"Xray working directory not found: {args.xray_workdir}")


def run_tuner(args: argparse.Namespace) -> pathlib.Path:
    validate_arguments(args)
    args.xray_bin = str(pathlib.Path(args.xray_bin).resolve())
    args.bench_bin = str(pathlib.Path(args.bench_bin).resolve())
    args.base_config = str(pathlib.Path(args.base_config).resolve())
    if args.xray_workdir:
        args.xray_workdir = str(pathlib.Path(args.xray_workdir).resolve())
    else:
        args.xray_workdir = str(pathlib.Path(args.base_config).parent)
    output_directory = pathlib.Path(args.output).resolve()
    output_directory.mkdir(parents=True, exist_ok=False)
    base_path = pathlib.Path(args.base_config).resolve()
    base_config = json.loads(base_path.read_text(encoding="utf-8"))
    candidates = generate_candidates(
        args.min_streams,
        args.max_connections,
        args.padding,
        not args.no_disabled,
        args.only_tcp[0],
    )
    baseline = [candidate for candidate in candidates if not candidate.enabled]
    enabled = [candidate for candidate in candidates if candidate.enabled]
    random.Random(args.seed).shuffle(enabled)
    candidates = baseline + enabled

    manifest = {
        "schema_version": 1,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "python": sys.version,
        "xray_bin": str(pathlib.Path(args.xray_bin).resolve()),
        "xray_sha256": sha256_file(args.xray_bin),
        "bench_bin": str(pathlib.Path(args.bench_bin).resolve()),
        "bench_sha256": sha256_file(args.bench_bin),
        "base_config": str(base_path),
        "xray_workdir": args.xray_workdir,
        "outbound_tag": args.outbound_tag,
        "target": args.target,
        "socks": args.socks,
        "interface": args.interface,
        "duration": args.duration,
        "warmup": args.warmup,
        "rounds": args.rounds,
        "parallel": args.parallel,
        "modes": args.modes,
        "seed": args.seed,
        "candidate_count": len(candidates),
    }
    write_json(output_directory / "manifest.json", manifest)

    results: list[CandidateResult] = []
    with tempfile.TemporaryDirectory(prefix="configs-", dir=output_directory) as temporary:
        temporary_directory = pathlib.Path(temporary)
        for candidate in candidates:
            results.append(
                run_candidate(args, base_config, candidate, output_directory, temporary_directory)
            )
    ranked = rank_candidates(results, require_baseline=not args.no_disabled)
    write_json(
        output_directory / "results.json",
        {
            "schema_version": 1,
            "ranked": [result.serializable() for result in ranked],
        },
    )
    write_summary_csv(output_directory / "summary.csv", ranked)
    write_report(output_directory / "REPORT.md", ranked)
    best = next((result for result in ranked if not result.error), None)
    if best is None:
        raise ValueError("no candidate completed successfully")
    best_config = patch_config(base_config, best.candidate, args.outbound_tag)
    write_json(output_directory / "best-config.json", best_config, mode=0o600)
    write_json(output_directory / "best-candidate.json", best.serializable())
    return output_directory


def main(argv: Optional[list[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        output = run_tuner(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
        return 2
    print(f"results: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
