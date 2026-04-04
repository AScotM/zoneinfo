#!/usr/bin/env python3

import argparse
import dataclasses
import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float


@dataclass
class HostProbe:
    host: str
    target: str
    is_local: bool
    reachable: bool
    error: str = ""
    hostname: str = ""
    fqdn: str = ""
    os_pretty_name: str = ""
    kernel: str = ""
    python_version: str = ""
    timezone: str = ""
    ntp_service_active: Optional[bool] = None
    ntp_synchronized: Optional[bool] = None
    local_rtc: Optional[bool] = None
    localtime_path: str = ""
    localtime_sha256: str = ""
    zoneinfo_path: str = ""
    zoneinfo_sha256: str = ""
    now_iso: str = ""
    now_epoch: Optional[int] = None
    utc_offset: str = ""
    tz_abbrev: str = ""
    timedatectl_available: bool = False
    source: str = ""
    warnings: List[str] = field(default_factory=list)
    raw_fields: Dict[str, str] = field(default_factory=dict)
    command_log: List[CommandResult] = field(default_factory=list)


@dataclass
class ComparisonIssue:
    category: str
    severity: str
    message: str
    hosts: List[str] = field(default_factory=list)


@dataclass
class ComparisonSummary:
    reference_host: str = ""
    timezone_consistent: bool = True
    localtime_target_consistent: bool = True
    localtime_hash_consistent: bool = True
    zoneinfo_hash_consistent: bool = True
    ntp_consistent: bool = True
    synchronized_consistent: bool = True
    utc_offset_consistent: bool = True
    clock_skew_within_threshold: bool = True
    max_clock_skew_seconds: Optional[int] = None
    issues: List[ComparisonIssue] = field(default_factory=list)


class Ansi:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


class RemoteExecutor:
    def __init__(
        self,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_options: Optional[List[str]] = None,
        connect_timeout: int = 5,
    ) -> None:
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.connect_timeout = connect_timeout
        self.ssh_options = ssh_options or []

    def run(self, target: str, command: str, is_local: bool) -> CommandResult:
        start = time.time()
        if is_local:
            proc = subprocess.run(
                ["bash", "-lc", command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        else:
            ssh_target = target
            if self.ssh_user and "@" not in target:
                ssh_target = f"{self.ssh_user}@{target}"
            ssh_cmd = [
                "ssh",
                "-p",
                str(self.ssh_port),
                "-o",
                f"ConnectTimeout={self.connect_timeout}",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ]
            ssh_cmd.extend(self.ssh_options)
            ssh_cmd.append(ssh_target)
            ssh_cmd.append(command)
            proc = subprocess.run(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        end = time.time()
        return CommandResult(
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=end - start,
        )


class HostInspector:
    REMOTE_SCRIPT = r"""
set -u

emit() {
  printf '%s=%s\n' "$1" "$2"
}

boolify() {
  case "${1:-}" in
    yes|true|1) printf 'true' ;;
    no|false|0) printf 'false' ;;
    *) printf 'unknown' ;;
  esac
}

sha256_of_file() {
  if [ -f "$1" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$1" | awk '{print $1}'
      return 0
    fi
    if command -v openssl >/dev/null 2>&1; then
      openssl dgst -sha256 "$1" | awk '{print $NF}'
      return 0
    fi
  fi
  printf ''
}

os_pretty_name=''
if [ -r /etc/os-release ]; then
  os_pretty_name=$(awk -F= '/^PRETTY_NAME=/{gsub(/^"/, "", $2); gsub(/"$/, "", $2); print $2}' /etc/os-release 2>/dev/null)
fi

hostname_short=$(hostname 2>/dev/null || printf '')
hostname_fqdn=$(hostname -f 2>/dev/null || printf '')
kernel=$(uname -srmo 2>/dev/null || printf '')
python_version=$(python3 -V 2>/dev/null | awk '{print $2}')
if [ -z "$python_version" ]; then
  python_version=$(python -V 2>/dev/null | awk '{print $2}')
fi

timedatectl_available=false
timezone=''
ntp_enabled='unknown'
ntp_synced='unknown'
local_rtc='unknown'

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl_available=true
  while IFS='=' read -r key value; do
    case "$key" in
      Timezone) timezone="$value" ;;
      NTP) ntp_enabled=$(boolify "$value") ;;
      NTPSynchronized) ntp_synced=$(boolify "$value") ;;
      LocalRTC) local_rtc=$(boolify "$value") ;;
    esac
  done < <(timedatectl show --property=Timezone --property=NTP --property=NTPSynchronized --property=LocalRTC 2>/dev/null)
fi

if [ -z "$timezone" ] && [ -r /etc/timezone ]; then
  timezone=$(head -n1 /etc/timezone 2>/dev/null)
fi

localtime_path=$(readlink -f /etc/localtime 2>/dev/null || printf '')
localtime_hash=$(sha256_of_file /etc/localtime)
zoneinfo_path=''
zoneinfo_hash=''

if [ -n "$timezone" ] && [ -f "/usr/share/zoneinfo/$timezone" ]; then
  zoneinfo_path="/usr/share/zoneinfo/$timezone"
  zoneinfo_hash=$(sha256_of_file "$zoneinfo_path")
fi

now_iso=$(date '+%Y-%m-%dT%H:%M:%S%z' 2>/dev/null || printf '')
now_epoch=$(date '+%s' 2>/dev/null || printf '')
utc_offset=$(date '+%z' 2>/dev/null || printf '')
tz_abbrev=$(date '+%Z' 2>/dev/null || printf '')

emit host_probe_version 1
emit hostname "$hostname_short"
emit fqdn "$hostname_fqdn"
emit os_pretty_name "$os_pretty_name"
emit kernel "$kernel"
emit python_version "$python_version"
emit timedatectl_available "$timedatectl_available"
emit timezone "$timezone"
emit ntp_service_active "$ntp_enabled"
emit ntp_synchronized "$ntp_synced"
emit local_rtc "$local_rtc"
emit localtime_path "$localtime_path"
emit localtime_sha256 "$localtime_hash"
emit zoneinfo_path "$zoneinfo_path"
emit zoneinfo_sha256 "$zoneinfo_hash"
emit now_iso "$now_iso"
emit now_epoch "$now_epoch"
emit utc_offset "$utc_offset"
emit tz_abbrev "$tz_abbrev"
"""

    def __init__(self, executor: RemoteExecutor, verbose: bool = False) -> None:
        self.executor = executor
        self.verbose = verbose

    def inspect(self, target: str, local_aliases: Sequence[str]) -> HostProbe:
        is_local = self._is_local_target(target, local_aliases)
        probe = HostProbe(host=target, target=target, is_local=is_local, reachable=False)

        result = self.executor.run(target, self.REMOTE_SCRIPT, is_local=is_local)
        probe.command_log.append(result)

        if result.returncode != 0:
            probe.error = self._clean_text(result.stderr) or f"probe failed with rc={result.returncode}"
            return probe

        raw = self._parse_key_value_output(result.stdout)
        probe.raw_fields = raw
        probe.reachable = True
        probe.hostname = raw.get("hostname", "")
        probe.fqdn = raw.get("fqdn", "")
        probe.os_pretty_name = raw.get("os_pretty_name", "")
        probe.kernel = raw.get("kernel", "")
        probe.python_version = raw.get("python_version", "")
        probe.timezone = raw.get("timezone", "")
        probe.ntp_service_active = self._parse_tri_bool(raw.get("ntp_service_active", "unknown"))
        probe.ntp_synchronized = self._parse_tri_bool(raw.get("ntp_synchronized", "unknown"))
        probe.local_rtc = self._parse_tri_bool(raw.get("local_rtc", "unknown"))
        probe.localtime_path = raw.get("localtime_path", "")
        probe.localtime_sha256 = raw.get("localtime_sha256", "")
        probe.zoneinfo_path = raw.get("zoneinfo_path", "")
        probe.zoneinfo_sha256 = raw.get("zoneinfo_sha256", "")
        probe.now_iso = raw.get("now_iso", "")
        probe.utc_offset = raw.get("utc_offset", "")
        probe.tz_abbrev = raw.get("tz_abbrev", "")
        probe.timedatectl_available = raw.get("timedatectl_available", "").lower() == "true"

        epoch_raw = raw.get("now_epoch", "")
        try:
            probe.now_epoch = int(epoch_raw) if epoch_raw else None
        except ValueError:
            probe.now_epoch = None

        if not probe.timezone:
            probe.warnings.append("timezone_unresolved")
        if not probe.localtime_path:
            probe.warnings.append("localtime_path_unresolved")
        if not probe.localtime_sha256:
            probe.warnings.append("localtime_hash_unresolved")
        if probe.timedatectl_available and probe.ntp_service_active is None:
            probe.warnings.append("ntp_state_unresolved")
        if probe.timedatectl_available and probe.ntp_synchronized is None:
            probe.warnings.append("sync_state_unresolved")
        if probe.zoneinfo_path and not probe.zoneinfo_sha256:
            probe.warnings.append("zoneinfo_hash_unresolved")

        probe.source = "local" if is_local else "ssh"
        return probe

    def _is_local_target(self, target: str, local_aliases: Sequence[str]) -> bool:
        lowered = target.strip().lower()
        if lowered in {"localhost", "127.0.0.1", "::1", socket.gethostname().lower(), socket.getfqdn().lower()}:
            return True
        return lowered in {x.lower() for x in local_aliases}

    def _parse_key_value_output(self, output: str) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for line in output.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip()
        return data

    def _parse_tri_bool(self, value: str) -> Optional[bool]:
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return None

    def _clean_text(self, value: str) -> str:
        return value.strip().replace("\r", "")


class Comparator:
    def __init__(self, skew_threshold_seconds: int = 3) -> None:
        self.skew_threshold_seconds = skew_threshold_seconds

    def compare(self, probes: List[HostProbe]) -> ComparisonSummary:
        summary = ComparisonSummary()
        reachable = [p for p in probes if p.reachable]
        if not reachable:
            summary.issues.append(
                ComparisonIssue(
                    category="reachability",
                    severity="critical",
                    message="No reachable hosts to compare",
                    hosts=[],
                )
            )
            return summary

        reference = reachable[0]
        summary.reference_host = reference.hostname or reference.host

        self._check_uniform_string(summary, reachable, "timezone", "timezone", "warning")
        self._check_uniform_string(summary, reachable, "localtime_path", "localtime_target", "warning")
        self._check_uniform_string(summary, reachable, "localtime_sha256", "localtime_hash", "warning")
        self._check_uniform_string(summary, reachable, "zoneinfo_sha256", "zoneinfo_hash", "warning")
        self._check_uniform_bool(summary, reachable, "ntp_service_active", "ntp", "warning")
        self._check_uniform_bool(summary, reachable, "ntp_synchronized", "synchronized", "warning")
        self._check_uniform_string(summary, reachable, "utc_offset", "utc_offset", "warning")

        epochs = [(p.hostname or p.host, p.now_epoch) for p in reachable if p.now_epoch is not None]
        if len(epochs) >= 2:
            only_values = [epoch for _, epoch in epochs]
            max_skew = max(only_values) - min(only_values)
            summary.max_clock_skew_seconds = max_skew
            if max_skew > self.skew_threshold_seconds:
                summary.clock_skew_within_threshold = False
                summary.issues.append(
                    ComparisonIssue(
                        category="clock_skew",
                        severity="warning",
                        message=f"Clock skew exceeds threshold: {max_skew}s > {self.skew_threshold_seconds}s",
                        hosts=[name for name, _ in epochs],
                    )
                )

        unreachable = [p for p in probes if not p.reachable]
        if unreachable:
            summary.issues.append(
                ComparisonIssue(
                    category="reachability",
                    severity="warning",
                    message=f"{len(unreachable)} host(s) unreachable",
                    hosts=[p.host for p in unreachable],
                )
            )

        unresolved = [p for p in reachable if p.warnings]
        if unresolved:
            summary.issues.append(
                ComparisonIssue(
                    category="partial_data",
                    severity="info",
                    message="Some hosts returned incomplete timezone or synchronization data",
                    hosts=[p.hostname or p.host for p in unresolved],
                )
            )

        return summary

    def _check_uniform_string(
        self,
        summary: ComparisonSummary,
        probes: List[HostProbe],
        attr: str,
        category: str,
        severity: str,
    ) -> None:
        values: Dict[str, List[str]] = {}
        for probe in probes:
            value = getattr(probe, attr)
            label = probe.hostname or probe.host
            values.setdefault(str(value), []).append(label)

        non_empty_values = [key for key in values.keys() if key]
        consistent = len(set(non_empty_values)) <= 1 if non_empty_values else True

        if category == "timezone":
            summary.timezone_consistent = consistent
        elif category == "localtime_target":
            summary.localtime_target_consistent = consistent
        elif category == "localtime_hash":
            summary.localtime_hash_consistent = consistent
        elif category == "zoneinfo_hash":
            summary.zoneinfo_hash_consistent = consistent
        elif category == "utc_offset":
            summary.utc_offset_consistent = consistent

        if not consistent:
            detail = "; ".join(f"{repr(value)} -> {', '.join(hosts)}" for value, hosts in values.items() if value)
            summary.issues.append(
                ComparisonIssue(
                    category=category,
                    severity=severity,
                    message=f"Inconsistent {category}: {detail}",
                    hosts=[probe.hostname or probe.host for probe in probes],
                )
            )

    def _check_uniform_bool(
        self,
        summary: ComparisonSummary,
        probes: List[HostProbe],
        attr: str,
        category: str,
        severity: str,
    ) -> None:
        values: Dict[str, List[str]] = {}
        for probe in probes:
            raw = getattr(probe, attr)
            key = "unknown" if raw is None else str(raw).lower()
            label = probe.hostname or probe.host
            values.setdefault(key, []).append(label)

        meaningful = [key for key in values.keys() if key != "unknown"]
        consistent = len(set(meaningful)) <= 1 if meaningful else True

        if category == "ntp":
            summary.ntp_consistent = consistent
        elif category == "synchronized":
            summary.synchronized_consistent = consistent

        if not consistent:
            detail = "; ".join(f"{value} -> {', '.join(hosts)}" for value, hosts in values.items())
            summary.issues.append(
                ComparisonIssue(
                    category=category,
                    severity=severity,
                    message=f"Inconsistent {category} state: {detail}",
                    hosts=[probe.hostname or probe.host for probe in probes],
                )
            )


class Formatter:
    def __init__(self, use_color: bool = True, width: int = 120) -> None:
        self.use_color = use_color
        self.width = max(width, 80)

    def _color(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"{code}{text}{Ansi.RESET}"

    def _ok(self, text: str) -> str:
        return self._color(text, Ansi.GREEN)

    def _warn(self, text: str) -> str:
        return self._color(text, Ansi.YELLOW)

    def _bad(self, text: str) -> str:
        return self._color(text, Ansi.RED)

    def _info(self, text: str) -> str:
        return self._color(text, Ansi.CYAN)

    def _title(self, text: str) -> str:
        return self._color(text, Ansi.BOLD)

    def render_table(self, probes: List[HostProbe], summary: ComparisonSummary) -> str:
        rows = []
        headers = [
            "host",
            "reachable",
            "timezone",
            "utc_offset",
            "tz",
            "ntp",
            "synced",
            "localtime_target",
            "local_sha256",
            "epoch",
        ]
        rows.append(headers)

        for p in probes:
            rows.append(
                [
                    p.hostname or p.host,
                    "yes" if p.reachable else "no",
                    p.timezone or "-",
                    p.utc_offset or "-",
                    p.tz_abbrev or "-",
                    self._bool_text(p.ntp_service_active),
                    self._bool_text(p.ntp_synchronized),
                    self._basename_or_full(p.localtime_path),
                    p.localtime_sha256[:12] if p.localtime_sha256 else "-",
                    str(p.now_epoch) if p.now_epoch is not None else "-",
                ]
            )

        widths = [0] * len(headers)
        for row in rows:
            for idx, cell in enumerate(row):
                widths[idx] = min(max(widths[idx], len(cell)), 40)

        lines = []
        lines.append(self._title("Timezone Consistency Report"))
        lines.append(self._rule())

        for idx, row in enumerate(rows):
            rendered = "  ".join(row[i].ljust(widths[i]) for i in range(len(row)))
            lines.append(rendered)
            if idx == 0:
                lines.append("  ".join("-" * widths[i] for i in range(len(row))))

        lines.append("")
        lines.extend(self._render_summary(summary))
        lines.append("")
        lines.extend(self._render_host_details(probes))
        return "\n".join(lines)

    def render_json(self, probes: List[HostProbe], summary: ComparisonSummary) -> str:
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": asdict(summary),
            "hosts": [asdict(p) for p in probes],
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    def _render_summary(self, summary: ComparisonSummary) -> List[str]:
        lines = [self._title("Summary"), self._rule()]
        checks = [
            ("timezone_consistent", summary.timezone_consistent),
            ("localtime_target_consistent", summary.localtime_target_consistent),
            ("localtime_hash_consistent", summary.localtime_hash_consistent),
            ("zoneinfo_hash_consistent", summary.zoneinfo_hash_consistent),
            ("ntp_consistent", summary.ntp_consistent),
            ("synchronized_consistent", summary.synchronized_consistent),
            ("utc_offset_consistent", summary.utc_offset_consistent),
            ("clock_skew_within_threshold", summary.clock_skew_within_threshold),
        ]
        for name, state in checks:
            marker = self._ok("OK") if state else self._bad("MISMATCH")
            lines.append(f"{name}: {marker}")

        if summary.max_clock_skew_seconds is not None:
            lines.append(f"max_clock_skew_seconds: {summary.max_clock_skew_seconds}")
        if summary.reference_host:
            lines.append(f"reference_host: {summary.reference_host}")

        if summary.issues:
            lines.append("")
            lines.append(self._title("Issues"))
            for issue in summary.issues:
                prefix = self._severity(issue.severity)
                host_part = f" [{', '.join(issue.hosts)}]" if issue.hosts else ""
                lines.append(f"- {prefix} {issue.category}: {issue.message}{host_part}")
        else:
            lines.append("")
            lines.append(self._ok("No comparison issues detected"))

        return lines

    def _render_host_details(self, probes: List[HostProbe]) -> List[str]:
        lines = [self._title("Host Details"), self._rule()]
        for p in probes:
            name = p.hostname or p.host
            status = self._ok("reachable") if p.reachable else self._bad("unreachable")
            lines.append(f"{name}: {status}")
            if not p.reachable:
                lines.append(f"  error: {p.error or 'unknown'}")
                continue
            lines.append(f"  target: {p.target}")
            lines.append(f"  source: {p.source}")
            lines.append(f"  fqdn: {p.fqdn or '-'}")
            lines.append(f"  os: {p.os_pretty_name or '-'}")
            lines.append(f"  kernel: {p.kernel or '-'}")
            lines.append(f"  python: {p.python_version or '-'}")
            lines.append(f"  timezone: {p.timezone or '-'}")
            lines.append(f"  utc_offset: {p.utc_offset or '-'}")
            lines.append(f"  tz_abbrev: {p.tz_abbrev or '-'}")
            lines.append(f"  ntp_service_active: {self._bool_text(p.ntp_service_active)}")
            lines.append(f"  ntp_synchronized: {self._bool_text(p.ntp_synchronized)}")
            lines.append(f"  local_rtc: {self._bool_text(p.local_rtc)}")
            lines.append(f"  localtime_path: {p.localtime_path or '-'}")
            lines.append(f"  localtime_sha256: {p.localtime_sha256 or '-'}")
            lines.append(f"  zoneinfo_path: {p.zoneinfo_path or '-'}")
            lines.append(f"  zoneinfo_sha256: {p.zoneinfo_sha256 or '-'}")
            lines.append(f"  now_iso: {p.now_iso or '-'}")
            lines.append(f"  now_epoch: {p.now_epoch if p.now_epoch is not None else '-'}")
            if p.warnings:
                lines.append(f"  warnings: {', '.join(p.warnings)}")
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        return lines

    def _rule(self) -> str:
        return "-" * min(self.width, 120)

    def _severity(self, value: str) -> str:
        if value == "critical":
            return self._bad("CRITICAL")
        if value == "warning":
            return self._warn("WARNING")
        return self._info("INFO")

    def _bool_text(self, value: Optional[bool]) -> str:
        if value is True:
            return "true"
        if value is False:
            return "false"
        return "unknown"

    def _basename_or_full(self, value: str) -> str:
        if not value:
            return "-"
        base = os.path.basename(value)
        if base and base != "localtime":
            return base
        return value


def read_hosts_from_file(path: str) -> List[str]:
    hosts: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            hosts.append(stripped)
    return hosts


def unique_preserve_order(values: Sequence[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare timezone, localtime, tzdata hashes, and clock state across Linux hosts")
    parser.add_argument("hosts", nargs="*", help="Hosts to inspect. Use localhost for local system.")
    parser.add_argument("--hosts-file", help="File with one host per line")
    parser.add_argument("--ssh-user", help="SSH username")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port")
    parser.add_argument("--ssh-option", action="append", default=[], help="Extra ssh option, may be repeated")
    parser.add_argument("--timeout", type=int, default=5, help="SSH connect timeout in seconds")
    parser.add_argument("--workers", type=int, default=8, help="Concurrent probe workers")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text report")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    parser.add_argument("--skew-threshold", type=int, default=3, help="Allowed clock skew in seconds")
    parser.add_argument("--show-commands", action="store_true", help="Show executed command metadata")
    parser.add_argument("--local-alias", action="append", default=[], help="Additional names treated as local")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if mismatches are found")
    return parser.parse_args()


def collect_targets(args: argparse.Namespace) -> List[str]:
    targets = list(args.hosts)
    if args.hosts_file:
        targets.extend(read_hosts_from_file(args.hosts_file))
    targets = unique_preserve_order(targets)
    if not targets:
        targets = ["localhost"]
    return targets


def print_command_logs(probes: List[HostProbe]) -> None:
    print("Command Execution")
    print("-" * 120)
    for probe in probes:
        name = probe.hostname or probe.host
        for entry in probe.command_log:
            print(f"host={name} rc={entry.returncode} duration={entry.duration_s:.3f}s command={shlex.quote(entry.command[:200])}")
            if entry.stderr.strip():
                print(f"stderr={entry.stderr.strip()}")
    print("")


def compute_exit_code(summary: ComparisonSummary, probes: List[HostProbe], strict: bool) -> int:
    if any(not p.reachable for p in probes):
        return 2 if strict else 0
    mismatch = any(
        not state
        for state in [
            summary.timezone_consistent,
            summary.localtime_target_consistent,
            summary.localtime_hash_consistent,
            summary.zoneinfo_hash_consistent,
            summary.ntp_consistent,
            summary.synchronized_consistent,
            summary.utc_offset_consistent,
            summary.clock_skew_within_threshold,
        ]
    )
    if mismatch and strict:
        return 3
    return 0


def main() -> None:
    args = parse_args()
    targets = collect_targets(args)

    if args.workers <= 0:
        print("workers must be positive", file=sys.stderr)
        sys.exit(1)

    executor = RemoteExecutor(
        ssh_user=args.ssh_user,
        ssh_port=args.ssh_port,
        ssh_options=args.ssh_option,
        connect_timeout=args.timeout,
    )
    inspector = HostInspector(executor=executor)
    comparator = Comparator(skew_threshold_seconds=args.skew_threshold)
    formatter = Formatter(use_color=not args.no_color and not args.json)

    probes: List[HostProbe] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        future_map = {
            pool.submit(inspector.inspect, target, args.local_alias): target
            for target in targets
        }
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                probe = future.result()
            except Exception as exc:
                probe = HostProbe(
                    host=target,
                    target=target,
                    is_local=False,
                    reachable=False,
                    error=f"internal_error: {exc}",
                )
            probes.append(probe)

    probes.sort(key=lambda p: targets.index(p.target))
    summary = comparator.compare(probes)

    if args.show_commands and not args.json:
        print_command_logs(probes)

    if args.json:
        print(formatter.render_json(probes, summary))
    else:
        print(formatter.render_table(probes, summary))

    sys.exit(compute_exit_code(summary, probes, args.strict))


if __name__ == "__main__":
    main()
