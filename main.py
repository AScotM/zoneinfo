#!/usr/bin/env python3
import argparse
import concurrent.futures
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any

VERSION = '2.0.0'

@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
    timed_out: bool = False

@dataclass
class Sample:
    t0: float
    t1: float
    remote_epoch: float | None
    offset: float | None
    uncertainty: float | None
    duration: float
    error: str = ''

@dataclass
class Finding:
    severity: str
    code: str
    host: str
    detail: str

@dataclass
class Host:
    target: str
    local: bool = False
    reachable: bool = False
    hostname: str = ''
    os_name: str = ''
    kernel: str = ''
    timezone: str = ''
    timezone_source: str = ''
    utc_offset: str = ''
    abbreviation: str = ''
    localtime_target: str = ''
    localtime_sha256: str = ''
    zoneinfo_sha256: str = ''
    tzdata_version: str = ''
    ntp_enabled: bool | None = None
    ntp_synchronized: bool | None = None
    rtc_local: bool | None = None
    chrony_active: bool | None = None
    chrony_tracking: dict[str, str] = field(default_factory=dict)
    chrony_sources: list[str] = field(default_factory=list)
    chrony_metrics: dict[str, float] = field(default_factory=dict)
    timesyncd_status: dict[str, str] = field(default_factory=dict)
    samples: list[Sample] = field(default_factory=list)
    offset_seconds: float | None = None
    uncertainty_seconds: float | None = None
    rtt_seconds: float | None = None
    raw: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

class Runner:
    def __init__(self, args: argparse.Namespace):
        self.args = args

    def execute(self, target: str, local: bool, script: str, timeout: float | None = None) -> CommandResult:
        if local:
            argv = ['bash', '-s']
        else:
            remote = target if '@' in target or not self.args.ssh_user else self.args.ssh_user + '@' + target
            argv = ['ssh', '-T', '-p', str(self.args.ssh_port), '-o', 'BatchMode=yes', '-o', 'NumberOfPasswordPrompts=0', '-o', 'ConnectTimeout=' + str(self.args.connect_timeout), '-o', 'StrictHostKeyChecking=' + self.args.host_key_policy]
            for option in self.args.ssh_option:
                argv.extend(['-o', option])
            argv.extend([remote, 'bash -s'])
        start = time.monotonic()
        try:
            p = subprocess.run(argv, input=script, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout or self.args.timeout, check=False)
            return CommandResult(argv, p.returncode, p.stdout, p.stderr, time.monotonic()-start)
        except subprocess.TimeoutExpired as e:
            return CommandResult(argv, 124, '', str(e), time.monotonic()-start, True)
        except OSError as e:
            return CommandResult(argv, 127, '', str(e), time.monotonic()-start)

PROBE = r'''
set +e
emit() { printf '%s=%s\n' "$1" "${2//$'\n'/ }"; }
first() { head -n 1; }
sha() { if [ -f "$1" ]; then if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'; fi; fi; }
kv() { local val; val=$(timedatectl show -p "$1" --value 2>/dev/null | first); emit "$2" "$val"; }
emit probe_version 2
emit hostname "$(hostname 2>/dev/null)"
emit os_name "$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | first | tr -d '"')"
emit kernel "$(uname -sr 2>/dev/null)"
if command -v timedatectl >/dev/null 2>&1; then
  kv Timezone timezone
  kv NTP ntp_enabled
  kv NTPSynchronized ntp_synchronized
  kv LocalRTC rtc_local
fi
emit timezone_file "$(cat /etc/timezone 2>/dev/null | first)"
emit localtime_target "$(readlink -f /etc/localtime 2>/dev/null)"
emit localtime_sha256 "$(sha /etc/localtime)"
emit utc_offset "$(date +%z 2>/dev/null)"
emit abbreviation "$(date +%Z 2>/dev/null)"
emit date_epoch "$(date +%s.%N 2>/dev/null)"
emit chrony_active "$(systemctl is-active chronyd 2>/dev/null)"
if command -v rpm >/dev/null 2>&1; then
  emit tzdata_version "$(rpm -q --qf '%{VERSION}-%{RELEASE}' tzdata 2>/dev/null | first)"
elif command -v dpkg-query >/dev/null 2>&1; then
  emit tzdata_version "$(dpkg-query -W -f='${Version}' tzdata 2>/dev/null | first)"
fi
if command -v chronyc >/dev/null 2>&1; then
  emit chrony_tracking "$(chronyc -n tracking 2>/dev/null | base64 -w0 2>/dev/null)"
  emit chrony_sources "$(chronyc -n sources -v 2>/dev/null | base64 -w0 2>/dev/null)"
fi
if command -v timedatectl >/dev/null 2>&1; then
  emit timesyncd_status "$(timedatectl timesync-status --no-pager 2>/dev/null | base64 -w0 2>/dev/null)"
fi
'''

CLOCK = "printf 'epoch=%s\\n' \"$(date +%s.%N)\"\n"

def parse_lines(data: str) -> dict[str, str]:
    result = {}
    for line in data.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if re.fullmatch(r'[a-z][a-z0-9_]*', key):
                result[key] = value.strip()
    return result

def tri(value: str) -> bool | None:
    value = value.lower().strip()
    if value in ('yes', 'true', '1', 'active'):
        return True
    if value in ('no', 'false', '0', 'inactive', 'failed'):
        return False
    return None

def decode64(value: str) -> str:
    if not value:
        return ''
    try:
        import base64
        return base64.b64decode(value, validate=True).decode('utf-8', 'replace')
    except (ValueError, UnicodeError):
        return ''

def parse_tracking(value: str) -> dict[str, str]:
    result = {}
    for line in value.splitlines():
        if ':' in line:
            key, data = line.split(':', 1)
            result[key.strip()] = data.strip()
    return result

def numeric_prefix(value: str) -> float | None:
    match = re.search(r'[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?', value)
    if not match:
        return None
    try:
        return float(match.group())
    except ValueError:
        return None

def local_names(args: argparse.Namespace) -> set[str]:
    return {'localhost', '127.0.0.1', '::1', socket.gethostname().lower(), socket.getfqdn().lower()} | {v.lower() for v in args.local_alias}

def inspect(target: str, args: argparse.Namespace, runner: Runner, aliases: set[str]) -> Host:
    h = Host(target=target, local=target.lower() in aliases)
    start = time.monotonic()
    response = runner.execute(target, h.local, PROBE)
    if response.returncode != 0:
        h.errors.append(('probe timeout' if response.timed_out else 'probe failed') + ': ' + (response.stderr.strip()[:250] or str(response.returncode)))
        h.elapsed_seconds = time.monotonic()-start
        return h
    d = parse_lines(response.stdout)
    if d.get('probe_version') != '2':
        h.errors.append('unexpected or incomplete probe response')
        h.elapsed_seconds = time.monotonic()-start
        return h
    h.reachable = True
    h.raw = d if args.include_raw else {}
    h.hostname = d.get('hostname', '')
    h.os_name = d.get('os_name', '')
    h.kernel = d.get('kernel', '')
    h.timezone = d.get('timezone', '')
    h.timezone_source = 'timedatectl' if h.timezone else ''
    if not h.timezone:
        h.timezone = d.get('timezone_file', '')
        h.timezone_source = '/etc/timezone' if h.timezone else ''
    h.localtime_target = d.get('localtime_target', '')
    if not h.timezone and '/zoneinfo/' in h.localtime_target:
        h.timezone = h.localtime_target.split('/zoneinfo/', 1)[1]
        h.timezone_source = 'localtime symlink'
    h.utc_offset = d.get('utc_offset', '')
    h.abbreviation = d.get('abbreviation', '')
    h.localtime_sha256 = d.get('localtime_sha256', '')
    h.tzdata_version = d.get('tzdata_version', '')
    h.ntp_enabled = tri(d.get('ntp_enabled', ''))
    h.ntp_synchronized = tri(d.get('ntp_synchronized', ''))
    h.rtc_local = tri(d.get('rtc_local', ''))
    h.chrony_active = tri(d.get('chrony_active', ''))
    h.chrony_tracking = parse_tracking(decode64(d.get('chrony_tracking', '')))
    h.chrony_sources = decode64(d.get('chrony_sources', '')).splitlines()
    h.timesyncd_status = parse_tracking(decode64(d.get('timesyncd_status', '')))
    for key, name in [('System time', 'system_time'), ('Last offset', 'last_offset'), ('RMS offset', 'rms_offset'), ('Root delay', 'root_delay'), ('Root dispersion', 'root_dispersion'), ('Update interval', 'update_interval'), ('Stratum', 'stratum'), ('Skew', 'skew')]:
        value = numeric_prefix(h.chrony_tracking.get(key, ''))
        if value is not None:
            h.chrony_metrics[name] = value
    if not h.timezone:
        h.warnings.append('timezone could not be resolved')
    if not h.localtime_sha256:
        h.warnings.append('/etc/localtime could not be hashed')
    if not h.tzdata_version:
        h.warnings.append('tzdata package version unavailable')
    if h.ntp_synchronized is None:
        h.warnings.append('system synchronization status unavailable')
    for _ in range(args.samples):
        t0 = time.time()
        c = runner.execute(target, h.local, CLOCK, timeout=args.sample_timeout)
        t1 = time.time()
        raw_epoch = parse_lines(c.stdout).get('epoch', '')
        try:
            epoch = float(raw_epoch)
            if not (1e9 < epoch < 1e11):
                raise ValueError('invalid epoch')
            offset = epoch - (t0+t1)/2
            uncertainty = (t1-t0)/2
            h.samples.append(Sample(t0, t1, epoch, offset, uncertainty, t1-t0))
        except ValueError:
            h.samples.append(Sample(t0, t1, None, None, None, t1-t0, c.stderr.strip()[:150] or 'invalid remote clock response'))
        if args.sample_interval and _ < args.samples-1:
            time.sleep(args.sample_interval)
    valid = [s for s in h.samples if s.offset is not None]
    if valid:
        best = min(valid, key=lambda s: s.duration)
        h.offset_seconds = best.offset
        h.uncertainty_seconds = best.uncertainty
        h.rtt_seconds = best.duration
    else:
        h.warnings.append('no valid clock samples')
    h.elapsed_seconds = time.monotonic()-start
    return h

def assess(hosts: list[Host], args: argparse.Namespace) -> list[Finding]:
    findings = []
    def add(severity: str, code: str, host: str, detail: str):
        findings.append(Finding(severity, code, host, detail))
    for h in hosts:
        if not h.reachable:
            add('critical', 'UNREACHABLE', h.target, '; '.join(h.errors))
            continue
        name = h.hostname or h.target
        if h.ntp_synchronized is False:
            add('critical', 'UNSYNCHRONIZED', name, 'timedatectl reports clock not synchronized')
        elif h.ntp_synchronized is None:
            add('info', 'SYNC_UNKNOWN', name, 'synchronization state unavailable')
        if h.ntp_enabled is False:
            add('warning', 'NTP_DISABLED', name, 'NTP management is disabled')
        if h.rtc_local is True:
            add('warning', 'LOCAL_RTC', name, 'RTC configured in local time')
        if h.offset_seconds is not None and h.uncertainty_seconds is not None:
            lower = max(0.0, abs(h.offset_seconds)-h.uncertainty_seconds)
            upper = abs(h.offset_seconds)+h.uncertainty_seconds
            if lower > args.skew_threshold:
                add('critical', 'CLOCK_OFFSET', name, f'estimated offset {h.offset_seconds:+.6f}s ±{h.uncertainty_seconds:.6f}s; exceeds {args.skew_threshold:.3f}s')
            elif upper > args.skew_threshold:
                add('warning', 'CLOCK_UNCERTAIN', name, f'offset {h.offset_seconds:+.6f}s ±{h.uncertainty_seconds:.6f}s overlaps threshold')
        if h.rtt_seconds is not None and h.rtt_seconds > args.rtt_warning:
            add('warning', 'HIGH_RTT', name, f'probe round trip {h.rtt_seconds:.3f}s; offset estimate is less precise')
        if h.chrony_active and not h.chrony_tracking:
            add('warning', 'CHRONY_UNAVAILABLE', name, 'chronyd active but tracking data unavailable')
        for w in h.warnings:
            add('info', 'PARTIAL_DATA', name, w)
    reachable = [h for h in hosts if h.reachable]
    if len(reachable) > 1:
        zones = {h.timezone for h in reachable if h.timezone}
        if len(zones) > 1:
            add('info', 'ZONE_VARIATION', '*', 'hosts use different timezone identifiers; this is not inherently an error')
        versions = {h.tzdata_version for h in reachable if h.tzdata_version}
        if len(versions) > 1:
            add('info', 'TZDATA_VARIATION', '*', 'tzdata package versions differ across hosts; cross-distribution release strings are not directly comparable')
        hashes = {}
        for h in reachable:
            if h.timezone and h.localtime_sha256:
                hashes.setdefault(h.timezone, set()).add(h.localtime_sha256)
        for zone, values in hashes.items():
            if len(values) > 1:
                add('warning', 'ZONE_RULE_VARIATION', '*', f'{zone} has different /etc/localtime content hashes')
        known = [(h, h.offset_seconds, h.uncertainty_seconds) for h in reachable if h.offset_seconds is not None and h.uncertainty_seconds is not None]
        for i, (a, ao, au) in enumerate(known):
            for b, bo, bu in known[i+1:]:
                delta = abs(ao-bo)
                if delta-au-bu > args.skew_threshold:
                    add('critical', 'INTERHOST_SKEW', '*', f'{a.target} vs {b.target}: estimated difference {delta:.6f}s, combined uncertainty {au+bu:.6f}s')
    order = {'critical': 0, 'warning': 1, 'info': 2}
    return sorted(findings, key=lambda f: (order[f.severity], f.host, f.code))

class Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled
    def color(self, s: str, code: str) -> str:
        return '\033['+code+'m'+s+'\033[0m' if self.enabled else s
    def title(self, s: str) -> str:
        return self.color(s, '1;36')
    def ok(self, s: str) -> str:
        return self.color(s, '32')
    def warn(self, s: str) -> str:
        return self.color(s, '33')
    def bad(self, s: str) -> str:
        return self.color(s, '31')
    def dim(self, s: str) -> str:
        return self.color(s, '2')

def pretty_bool(value: bool | None) -> str:
    return 'yes' if value is True else 'no' if value is False else '?'

def table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [min(36, max(len(str(row[i])) for row in [headers]+rows)) for i in range(len(headers))]
    def line(row):
        return '  '.join(str(value)[:widths[i]].ljust(widths[i]) for i, value in enumerate(row))
    return '\n'.join([line(headers), line(['-'*w for w in widths])]+[line(r) for r in rows])

def render(hosts: list[Host], findings: list[Finding], args: argparse.Namespace, started: float) -> str:
    p = Palette(args.color == 'always' or (args.color == 'auto' and sys.stdout.isatty()))
    lines = [p.title('ZONEINFO / DISTRIBUTED TIME FORENSICS'), p.dim(f'version {VERSION}  |  hosts {len(hosts)}  |  elapsed {time.monotonic()-started:.2f}s'), '']
    rows = []
    for h in hosts:
        offset = f'{h.offset_seconds:+.5f}' if h.offset_seconds is not None else '-'
        uncertainty = f'{h.uncertainty_seconds:.5f}' if h.uncertainty_seconds is not None else '-'
        rows.append([h.hostname or h.target, 'UP' if h.reachable else 'DOWN', h.timezone or '-', h.utc_offset or '-', pretty_bool(h.ntp_synchronized), pretty_bool(h.chrony_active), offset, uncertainty])
    lines.extend([p.title('FLEET OVERVIEW'), table(['HOST','STATE','TIMEZONE','UTC','SYNC','CHRONY','OFFSET(s)','ERROR(±s)'], rows), ''])
    lines.append(p.title('FINDINGS'))
    if not findings:
        lines.append(p.ok('No findings'))
    for f in findings:
        severity = p.bad(f.severity.upper()) if f.severity == 'critical' else p.warn(f.severity.upper()) if f.severity == 'warning' else p.dim(f.severity.upper())
        lines.append(f'{severity:>8}  {f.code:<22} {f.host}: {f.detail}')
    lines.append('')
    for h in hosts:
        lines.append(p.title('HOST / '+(h.hostname or h.target)))
        lines.append(f'  target={h.target} transport={"local" if h.local else "ssh"} reachable={h.reachable} elapsed={h.elapsed_seconds:.3f}s')
        if not h.reachable:
            lines.extend('  error='+e for e in h.errors)
            lines.append('')
            continue
        for label, value in [('operating system', h.os_name), ('kernel', h.kernel), ('timezone', h.timezone), ('timezone source', h.timezone_source), ('UTC offset', h.utc_offset), ('abbreviation', h.abbreviation), ('localtime target', h.localtime_target), ('localtime sha256', h.localtime_sha256), ('tzdata package', h.tzdata_version), ('NTP enabled', pretty_bool(h.ntp_enabled)), ('synchronized', pretty_bool(h.ntp_synchronized)), ('RTC local', pretty_bool(h.rtc_local)), ('chronyd active', pretty_bool(h.chrony_active))]:
            lines.append(f'  {label:<20} {value or "-"}')
        if h.offset_seconds is not None:
            lines.append(f'  estimated offset     {h.offset_seconds:+.9f}s ±{h.uncertainty_seconds:.9f}s (minimum RTT sample)')
        if h.chrony_tracking:
            lines.append('  CHRONY TRACKING')
            for key, value in h.chrony_tracking.items():
                lines.append(f'    {key:<24} {value}')
        if h.chrony_sources and args.show_sources:
            lines.append('  CHRONY SOURCES')
            lines.extend('    '+line for line in h.chrony_sources)
        if h.timesyncd_status and args.show_timesyncd:
            lines.append('  TIMESYNCD')
            for key, value in h.timesyncd_status.items():
                lines.append(f'    {key:<24} {value}')
        if args.show_samples:
            lines.append('  CLOCK SAMPLES')
            for i, sample in enumerate(h.samples, 1):
                lines.append(f'    {i:02d}  RTT={sample.duration:.6f}s offset={sample.offset if sample.offset is not None else "?"} uncertainty={sample.uncertainty if sample.uncertainty is not None else "?"} {sample.error}')
        lines.append('')
    lines.extend([p.dim('Clock estimates use midpoint timing and an RTT/2 uncertainty bound.'), p.dim('This is not a replacement for chrony measurements or an NTP protocol implementation.')])
    return '\n'.join(lines)

def targets_from_args(args: argparse.Namespace) -> list[str]:
    targets = list(args.hosts)
    if args.hosts_file:
        for line in pathlib.Path(args.hosts_file).read_text(encoding='utf-8').splitlines():
            item = line.strip()
            if item and not item.startswith('#'):
                targets.append(item)
    return list(dict.fromkeys(targets or ['localhost']))

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Zoneinfo v2: distributed Linux timezone, chrony and clock forensics')
    parser.add_argument('hosts', nargs='*')
    parser.add_argument('--hosts-file')
    parser.add_argument('--ssh-user')
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--ssh-option', action='append', default=[])
    parser.add_argument('--host-key-policy', choices=['yes','accept-new'], default='yes')
    parser.add_argument('--connect-timeout', type=int, default=5)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--sample-timeout', type=float, default=8)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--samples', type=int, default=5)
    parser.add_argument('--sample-interval', type=float, default=0.05)
    parser.add_argument('--skew-threshold', type=float, default=3.0)
    parser.add_argument('--rtt-warning', type=float, default=1.0)
    parser.add_argument('--local-alias', action='append', default=[])
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--json-file')
    parser.add_argument('--include-raw', action='store_true')
    parser.add_argument('--show-samples', action='store_true')
    parser.add_argument('--show-sources', action='store_true')
    parser.add_argument('--show-timesyncd', action='store_true')
    parser.add_argument('--color', choices=['auto','always','never'], default='auto')
    parser.add_argument('--strict', action='store_true')
    parser.add_argument('--fail-on-warning', action='store_true')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    if args.workers < 1 or not 1 <= args.samples <= 100 or args.sample_interval < 0 or args.timeout <= 0 or args.sample_timeout <= 0 or args.skew_threshold < 0 or args.rtt_warning <= 0 or not 1 <= args.ssh_port <= 65535 or args.connect_timeout < 1:
        parser.error('invalid worker, sample, timeout, threshold or SSH settings')
    return args

def main() -> int:
    args = parse_args()
    started = time.monotonic()
    try:
        targets = targets_from_args(args)
    except OSError as exc:
        print(f'zoneinfo: cannot read host list: {exc}', file=sys.stderr)
        return 1
    runner = Runner(args)
    aliases = local_names(args)
    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(inspect, target, args, runner, aliases): target for target in targets}
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                result[target] = future.result()
            except Exception as exc:
                result[target] = Host(target=target, errors=[f'internal probe error: {exc}'])
    hosts = [result[target] for target in targets]
    findings = assess(hosts, args)
    generated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = {'tool':'zoneinfo', 'version':VERSION, 'generated_at':generated, 'duration_seconds':time.monotonic()-started, 'hosts':[dataclasses.asdict(h) for h in hosts], 'findings':[dataclasses.asdict(f) for f in findings], 'summary':{'total':len(hosts), 'reachable':sum(h.reachable for h in hosts), 'critical':sum(f.severity=='critical' for f in findings), 'warning':sum(f.severity=='warning' for f in findings), 'info':sum(f.severity=='info' for f in findings)}}
    serialized = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.json_file:
        try:
            pathlib.Path(args.json_file).write_text(serialized+'\n', encoding='utf-8')
        except OSError as exc:
            print(f'zoneinfo: cannot write JSON: {exc}', file=sys.stderr)
            return 1
    print(serialized if args.json else render(hosts, findings, args, started))
    if args.strict:
        if any(not h.reachable for h in hosts):
            return 2
        if any(f.severity=='critical' or (args.fail_on_warning and f.severity=='warning') for f in findings):
            return 3
    return 0

if __name__ == '__main__':
    sys.exit(main())
