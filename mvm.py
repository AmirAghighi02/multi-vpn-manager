#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mvm.py -- Multi-VPN Manager: one control center for NetworkManager VPNs (OpenVPN, L2TP/IPsec, ...)
and sshuttle tunnels, with split-tunnel routing that coexists with Windscribe / ExpressVPN / v2ray etc.

Copy THIS file to any Linux box (Python 3.10+) and run:

    python3 mvm.py              # the TUI (offers to install textual + rich into ./.venv)
    python3 mvm.py doctor       # troubleshooting (works with no packages at all)
    python3 mvm.py sudoers install   # one-time: password-less ip/sshuttle for this user

What it does
  * lists the VPNs defined in the GUI (NetworkManager) + your sshuttle profiles
  * per VPN: which IPs/CIDRs go through it (split tunnel, never the default route)
  * up / down / restart, live status (interface, gateway, uptime, traffic, route health)
  * reads credentials state from the GUI profile (saved / keyring / always-ask) and can store them
  * routing map: VPN -> routes -> where each IP really goes right now
  * per-VPN logs (own log + NetworkManager / pppd / openvpn journal lines)
  * doctor with fix hints and one-key fixes
  * detects other VPNs (Windscribe, ExpressVPN, v2ray/xray/sing-box/clash, WireGuard, plain openvpn)
    and keeps out of their way: /32 routes in main + a `to IP lookup main` rule, exclusions cleaned
  * optional autostart per VPN (systemd --user unit)

Run it as your normal desktop user (NOT with sudo): NetworkManager secrets live in your session keyring.
State lives next to this file: configs/ logs/ state/ backups/ .venv/ .mvm.json

Sub-commands: list status up down restart apply routes adopt new-sshuttle delete secrets doctor
              logs graph foreign autostart sudoers bootstrap
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import getpass
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

VERSION = "1.0"
BASE = Path(__file__).resolve().parent
SETTINGS_FILE = BASE / ".mvm.json"
VENV_DIR = BASE / ".venv"
CONFIGS = BASE / "configs"
LOGS = BASE / "logs"
STATE = BASE / "state"
BACKUPS = BASE / "backups"
REQ_PACKAGES = ["textual>=0.86", "rich>=13.7"]
SUDOERS_FILE = "/etc/sudoers.d/multi-vpn-manager"
RULE_PRIO = 30          # our `to IP lookup main` policy rules sit before foreign VPN rules
LOG_MAX = 1_000_000

# palette (Tokyo-night-ish)
C_BG = "#1a1b26"
C_PANEL = "#24283b"
C_TEXT = "#c0caf5"
C_MUTED = "#565f89"
C_BLUE = "#7aa2f7"
C_CYAN = "#7dcfff"
C_PURPLE = "#bb9af7"
C_GREEN = "#9ece6a"
C_YELLOW = "#e0af68"
C_ORANGE = "#ff9e64"
C_RED = "#f7768e"
C_PINK = "#ff7eb6"
GRAD_MAIN = [C_CYAN, C_BLUE, C_PURPLE, C_PINK]
GRAD_OK = ["#73daca", C_GREEN, "#c3e88d"]
GRAD_WARM = [C_GREEN, C_YELLOW, C_ORANGE, C_RED]

KINDS = ("nm-openvpn", "nm-l2tp", "nm-wireguard", "nm-other", "sshuttle")
KIND_LABEL = {"nm-openvpn": "OpenVPN", "nm-l2tp": "L2TP/IPsec", "nm-wireguard": "WireGuard", "nm-other": "NM VPN", "sshuttle": "sshuttle"}


# ======================================================================================
# 1. bootstrap
# ======================================================================================
def can_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def venv_python() -> Path:
    return VENV_DIR / "bin/python"


def in_venv() -> bool:
    try:  # .venv/bin/python is a symlink to the system python: compare prefixes, not executables
        return Path(sys.prefix).resolve() == VENV_DIR.resolve()
    except OSError:
        return False


def reexec_into_venv_if_needed() -> None:
    if os.environ.get("MVM_REEXEC") == "1" or os.environ.get("MVM_NO_VENV") == "1":
        return
    if can_import("textual") and can_import("rich"):
        return
    vp = venv_python()
    if vp.exists() and not in_venv():
        os.execve(str(vp), [str(vp), str(Path(__file__).resolve())] + sys.argv[1:], dict(os.environ, MVM_REEXEC="1"))


def bootstrap(say: Callable[[str], None] = print) -> bool:
    try:
        if not venv_python().exists():
            say("creating virtualenv in %s ..." % VENV_DIR)
            subprocess.check_call([sys.executable, "-m", "venv", str(VENV_DIR)])
        say("installing %s ..." % ", ".join(REQ_PACKAGES))
        subprocess.check_call([str(venv_python()), "-m", "pip", "install", "--quiet", "--upgrade"] + REQ_PACKAGES)
        say("done.")
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        say("bootstrap failed: %s" % e)
        if not can_import("ensurepip"):
            say("this python has no venv support. On Debian/Ubuntu:  sudo apt install python3-venv")
        say("manual alternative:  python3 -m venv .venv && .venv/bin/pip install %s" % " ".join(REQ_PACKAGES))
        return False


COLOR_MODES = {"truecolor": "truecolor", "256": "256", "16": "standard"}


def configure_colors(choice: str = "auto") -> str:
    """Pick the colour mode BEFORE textual/rich are used.
    Default = 24-bit true colour: SSH, sudo, tmux and screen often drop COLORTERM, and then the dark palette gets
    squeezed into 256 colours (base16 themes turn the backgrounds peach). Force with --colors / MVM_COLORS / Settings."""
    choice = os.environ.get("MVM_COLORS", choice) or "auto"
    if choice == "auto":
        if os.environ.get("TEXTUAL_COLOR_SYSTEM"):          # the user already decided
            return os.environ["TEXTUAL_COLOR_SYSTEM"]
        term = os.environ.get("TERM", "")
        if os.environ.get("NO_COLOR") or term in ("", "linux", "dumb"):   # real Linux console: let the libraries detect
            return "auto"
        choice = "truecolor"
    mode = COLOR_MODES.get(choice, "truecolor")
    os.environ["TEXTUAL_COLOR_SYSTEM"] = mode
    if mode == "truecolor":
        os.environ["COLORTERM"] = "truecolor"                # rich (CLI output) + child processes see it too
    return mode


# ======================================================================================
# 2. settings + helpers
# ======================================================================================
def default_settings() -> Dict[str, Any]:
    return {
        "refresh_interval": 3,
        "connect_timeout": 40,
        "clean_tables": ["main", "windscribe"],   # tables whose /32 exclusions for our IPs are removed first
        "policy_rules": True,                    # add `to IP lookup main prio 30` so foreign policy routing can't steal our IPs
        "journal_minutes": 180,
        "colors": "auto",
        "probe_interval": 15,                    # seconds between health-probe rounds (TUI)
        "dns_refresh": 300,                      # seconds before hostnames in route lists are resolved again
        "notifications": True,                   # desktop notifications (notify-send)
        "hidden_profiles": [],                   # VPN rows hidden in the TUI list
        "op_view": "inline",                     # inline (progress in the row) | popup (live log dialog)
    }


def load_settings() -> Dict[str, Any]:
    s = default_settings()
    try:
        s.update(json.loads(SETTINGS_FILE.read_text()))
    except (OSError, ValueError):
        pass
    return s


def save_settings(s: Dict[str, Any]) -> None:
    atomic_write(SETTINGS_FILE, json.dumps(s, indent=2) + "\n")


def atomic_write(path: Path, text: str, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp%d" % os.getpid())
    tmp.write_text(text)
    if mode is not None:
        os.chmod(tmp, mode)
    os.replace(tmp, path)


def human_bytes(n: float) -> str:
    n = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024:
            return ("%.0f %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024
    return "%.1f PiB" % n


def human_dur(sec: Optional[float]) -> str:
    if sec is None or sec < 0:
        return "-"
    sec = int(sec)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return "%dd %02dh" % (d, h)
    if h:
        return "%dh %02dm" % (h, m)
    if m:
        return "%dm %02ds" % (m, s)
    return "%ds" % s


def sh(cmd: List[str], timeout: float = 20, input: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    try:
        kw: Dict[str, Any] = {"capture_output": True, "text": True, "timeout": timeout, "env": env}
        if input is None:
            kw["stdin"] = subprocess.DEVNULL
        else:
            kw["input"] = input
        p = subprocess.run(cmd, **kw)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: timed out after %ss" % (cmd[0], timeout)
    except OSError as e:
        return 126, "", str(e)


def which(name: str, *fallbacks: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for f in fallbacks:
        if os.access(f, os.X_OK):
            return f
    return None


IP = which("ip", "/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip") or "ip"
NMCLI = which("nmcli") or "nmcli"
KILL = which("kill", "/usr/bin/kill", "/bin/kill") or "/usr/bin/kill"


def priv(cmd: List[str], timeout: float = 15) -> Tuple[int, str, str]:
    """run a privileged command without ever prompting (sudo -n). Needs the sudoers drop-in (`mvm sudoers install`)."""
    if os.geteuid() == 0:
        return sh(cmd, timeout)
    return sh(["sudo", "-n"] + cmd, timeout)


def slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", s.strip()).strip("-.")
    return s or "vpn"


def now() -> float:
    return time.time()


# ---------------------------------------------------------------- per-VPN log
_log_lock = threading.Lock()


def log_path(name: str) -> Path:
    return LOGS / ("%s.log" % name)


def vlog(name: str, msg: str, level: str = "INFO") -> str:
    line = "%s %-5s %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), level, msg)
    with _log_lock:
        try:
            LOGS.mkdir(parents=True, exist_ok=True)
            p = log_path(name)
            if p.exists() and p.stat().st_size > LOG_MAX:
                os.replace(p, p.with_suffix(".log.1"))
            with p.open("a") as f:
                f.write(line + "\n")
        except OSError:
            pass
    return line


class Say:
    """log to the VPN's log file AND to a UI callback"""
    def __init__(self, name: str, out: Optional[Callable[[str], None]] = None) -> None:
        self.name, self.out = name, out

    def __call__(self, msg: str, level: str = "INFO") -> None:
        vlog(self.name, msg, level)
        if self.out:
            prefix = {"ERROR": "✖ ", "WARN": "⚠ ", "OK": "✔ "}.get(level, "  ")
            self.out(prefix + msg)


# ======================================================================================
# 3. config model
# ======================================================================================
def default_config(name: str, kind: str) -> Dict[str, Any]:
    return {"name": name, "kind": kind, "nm_uuid": "", "nm_name": "", "routes": [], "gateway": "auto",
            "autostart": False, "never_default": True, "ssh_remote": "", "ssh_args": "", "note": "",
            "probes": [], "notify": True}


@dataclass
class Issue:
    level: str   # error | warn
    msg: str
    where: str = ""


def norm_route(r: str) -> Optional[str]:
    """'1.2.3.4' -> '1.2.3.4/32'; '10.0.0.0/8' stays; invalid -> None"""
    r = r.strip()
    if not r:
        return None
    try:
        return str(ipaddress.ip_network(r, strict=False))
    except ValueError:
        return None


def short_route(r: str) -> str:
    return r[:-3] if r.endswith("/32") else r


MAX_RANGE_PREFIXES = 64


def _range_bounds(tok: str) -> Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]:
    """'10.0.0.5-10.0.0.20' | '10.0.0.5-20' | '10.1.2.*' | '10.1.*.*' -> (first, last); else None"""
    tok = tok.strip().replace("–", "-").replace("—", "-")
    try:
        if "*" in tok:
            parts = tok.split(".")
            if len(parts) != 4 or "*" not in parts:
                return None
            stars = [i for i, x in enumerate(parts) if x == "*"]
            if stars != list(range(4 - len(stars), 4)) or any(x == "*" or not x.isdigit() for x in parts[:4 - len(stars)]):
                return None   # only trailing wildcards: 10.1.2.*  10.1.*.*
            lo = ipaddress.IPv4Address(".".join(x if x != "*" else "0" for x in parts))
            hi = ipaddress.IPv4Address(".".join(x if x != "*" else "255" for x in parts))
            return lo, hi
        if tok.count("-") != 1:
            return None
        a, b = tok.split("-")
        lo = ipaddress.IPv4Address(a.strip())
        b = b.strip()
        if b.isdigit():          # shorthand: last octet only
            hi = ipaddress.IPv4Address(a.strip().rsplit(".", 1)[0] + "." + b)
        else:
            hi = ipaddress.IPv4Address(b)
        return lo, hi
    except (ValueError, ipaddress.AddressValueError):
        return None


def norm_entry(tok: str) -> Optional[str]:
    """canonical form of a route entry: CIDR ('1.2.3.4/32', '10.0.0.0/8') or range ('10.0.0.5-10.0.0.20').
    A range that is exactly one CIDR block is stored as that CIDR. Invalid / reversed -> None."""
    tok = str(tok).strip()
    if not tok:
        return None
    if is_host(tok):
        return tok.lower().rstrip(".")
    b = _range_bounds(tok)
    if b:
        lo, hi = b
        if hi < lo:
            return None
        nets = list(ipaddress.summarize_address_range(lo, hi))
        return str(nets[0]) if len(nets) == 1 else "%s-%s" % (lo, hi)
    return norm_route(tok)


def is_range(entry: str) -> bool:
    return bool(re.fullmatch(r"[\d.]+-[\d.]+", entry or ""))


HOST_RX = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))+$")


def is_host(entry: str) -> bool:
    e = (entry or "").rstrip(".")
    if re.fullmatch(r"[\d.*/-]+", e):   # IPs, CIDRs, ranges, wildcards: never a hostname
        return False
    return bool(HOST_RX.match(e)) and not re.search(r"\.\d+$", e)


# ---------------------------------------------------------------- hostname resolution (cached)
DNS_CACHE_FILE = STATE / "dns-cache.json"
_dns_lock = threading.Lock()
_dns: Dict[str, Dict[str, Any]] = {}


def _dns_load() -> None:
    global _dns
    if not _dns:
        try:
            _dns = json.loads(DNS_CACHE_FILE.read_text())
        except (OSError, ValueError):
            _dns = {}


def resolve_host(host: str, max_age: Optional[float] = None, timeout: float = 5) -> Tuple[List[str], str]:
    """IPv4 addresses of host (cached for settings.dns_refresh seconds). Returns (ips, error)."""
    host = host.lower().rstrip(".")
    with _dns_lock:
        _dns_load()
        ent = _dns.get(host)
    if max_age is None:
        max_age = float(load_settings().get("dns_refresh", 300))
    if ent and now() - ent.get("ts", 0) < max_age and ent.get("ips"):
        return list(ent["ips"]), ""
    box_: Dict[str, Any] = {}

    def look() -> None:
        try:
            box_["ips"] = sorted({a[4][0] for a in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)},
                                 key=lambda x: tuple(int(p) for p in x.split(".")))
        except OSError as e:
            box_["err"] = str(e)
    th = threading.Thread(target=look, daemon=True)
    th.start()
    th.join(timeout)
    ips, err = box_.get("ips", []), box_.get("err", "" if box_ else "DNS lookup timed out")
    with _dns_lock:
        if ips:
            _dns[host] = {"ips": ips, "ts": now()}
            try:
                atomic_write(DNS_CACHE_FILE, json.dumps(_dns, indent=1))
            except OSError:
                pass
        elif ent and ent.get("ips"):
            return list(ent["ips"]), "lookup failed (%s) — using last known IPs" % err
    return ips, err


def cached_host(host: str) -> List[str]:
    with _dns_lock:
        _dns_load()
        return list((_dns.get(host.lower().rstrip(".")) or {}).get("ips", []))


def expand_entry(entry: str, resolve: bool = True) -> List[str]:
    """route entry -> the minimal list of CIDR prefixes the kernel gets.
    Hostnames resolve to /32s (resolve=False: use the cache only, never touch the network)."""
    n = norm_entry(entry)
    if not n:
        return []
    if is_host(n):
        ips = resolve_host(n)[0] if resolve else cached_host(n)
        return ["%s/32" % ip for ip in ips]
    if not is_range(n):
        return [n]
    lo, hi = (ipaddress.IPv4Address(x) for x in n.split("-"))
    return [str(x) for x in ipaddress.summarize_address_range(lo, hi)]


def expand_routes(entries: List[str], resolve: bool = False) -> List[str]:
    """all kernel prefixes of a route list. resolve=False (default) uses the DNS cache for hostnames: no network."""
    out: List[str] = []
    for e in entries or []:
        out += expand_entry(str(e), resolve)
    return list(dict.fromkeys(out))


def route_sources(entries: List[str]) -> Dict[str, str]:
    """expanded CIDR -> the range / hostname entry it came from"""
    res = {}
    for e in entries or []:
        n = norm_entry(str(e))
        if n and (is_range(n) or is_host(n)):
            for x in expand_entry(n, resolve=False):
                res.setdefault(x, n)
    return res


def host_entries(entries: List[str]) -> List[str]:
    return [n for n in (norm_entry(str(e)) for e in entries or []) if n and is_host(n)]


def entry_label(entry: str) -> str:
    """range shown with its size, CIDR shown short"""
    n = norm_entry(entry) or entry
    if is_range(n):
        lo, hi = (ipaddress.IPv4Address(x) for x in n.split("-"))
        return "%s – %s (%d IPs)" % (lo, hi, int(hi) - int(lo) + 1)
    if is_host(n):
        ips = cached_host(n)
        return "%s (%s)" % (n, ("%d IP%s" % (len(ips), "" if len(ips) == 1 else "s")) if ips else "not resolved yet")
    return short_route(n)


def parse_routes_text(text: str) -> Tuple[List[str], List[str]]:
    good, bad = [], []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().replace("–", "-").replace("—", "-")
        line = re.sub(r"\s*-\s*", "-", line)          # '10.0.0.1 - 10.0.0.9' -> one token
        for tok in re.split(r"[\s,;]+", line):
            if not tok:
                continue
            n = norm_entry(tok)
            (good if n else bad).append(n or tok)
    seen, out = set(), []
    for g in good:
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out, bad


def validate_config(c: Dict[str, Any], others: Optional[List[Dict[str, Any]]] = None) -> List[Issue]:
    iss: List[Issue] = []
    name = str(c.get("name", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", name):
        iss.append(Issue("error", "name must be 1-48 chars of letters, digits, . _ -", "name"))
    if c.get("kind") not in KINDS:
        iss.append(Issue("error", "unknown kind %r" % c.get("kind"), "kind"))
    routes = c.get("routes") or []
    if not isinstance(routes, list):
        iss.append(Issue("error", "routes must be a list", "routes"))
        routes = []
    for r in routes:
        n = norm_entry(str(r))
        if not n:
            iss.append(Issue("error", "invalid entry %r (IP, CIDR, a.b.c.d-e.f.g.h, a.b.c.d-N, a.b.c.*, or a hostname)" % r, "routes"))
            continue
        if is_host(n):
            continue   # resolved when routes are applied (and re-resolved every dns_refresh seconds)
        exp = expand_entry(n)
        if any(x.endswith("/0") for x in exp):
            iss.append(Issue("error", "%s would replace the default route (not a split tunnel)" % r, "routes"))
        elif is_range(n) and len(exp) > MAX_RANGE_PREFIXES:
            iss.append(Issue("error", "range %s needs %d prefixes (max %d) — use a CIDR instead" % (r, len(exp), MAX_RANGE_PREFIXES), "routes"))
    total = len(expand_routes(routes))
    if total > 1000:
        iss.append(Issue("warn", "%d kernel routes after expanding ranges — that is a lot" % total, "routes"))
    if not routes:
        iss.append(Issue("warn", "no routes: the tunnel will come up but nothing is sent through it", "routes"))
    for t in c.get("probes") or []:
        if not parse_probe(str(t)):
            iss.append(Issue("error", "invalid probe %r (host:port · http(s)://url · ping:host)" % t, "probes"))
    gw = str(c.get("gateway") or "auto")
    if gw != "auto":
        try:
            ipaddress.ip_address(gw)
        except ValueError:
            iss.append(Issue("error", "gateway must be 'auto' or an IP", "gateway"))
    if c.get("kind") == "sshuttle":
        if not re.fullmatch(r"[^\s@]+@[^\s:]+(:\d+)?|[^\s@:]+(:\d+)?", str(c.get("ssh_remote", ""))):
            iss.append(Issue("error", "ssh remote must look like user@host[:port] (or a ~/.ssh/config alias)", "ssh_remote"))
        try:
            shlex.split(str(c.get("ssh_args", "")))
        except ValueError as e:
            iss.append(Issue("error", "extra sshuttle args: %s" % e, "ssh_args"))
    elif not c.get("nm_uuid") and not c.get("nm_name"):
        iss.append(Issue("error", "not linked to a NetworkManager profile", "nm"))
    for o in others or []:
        if o.get("name") == name:
            continue
        common = set(expand_routes(routes)) & set(expand_routes(o.get("routes") or []))
        if common:
            iss.append(Issue("warn", "%d route(s) also claimed by '%s' (the VPN brought up last wins): %s"
                             % (len(common), o.get("name"), ", ".join(sorted(short_route(x) for x in common)[:4])), "routes"))
    return iss


def config_path(name: str) -> Path:
    return CONFIGS / ("%s.json" % name)


def load_configs() -> List[Dict[str, Any]]:
    out = []
    for p in sorted(CONFIGS.glob("*.json")):
        try:
            c = json.loads(p.read_text())
            base = default_config(p.stem, c.get("kind", "nm-other"))
            base.update(c)
            base["name"] = p.stem
            out.append(base)
        except (OSError, ValueError):
            out.append(dict(default_config(p.stem, "nm-other"), broken=True))
    return out


def save_config(c: Dict[str, Any]) -> None:
    c = {k: v for k, v in c.items() if k != "broken"}
    c["routes"] = list(dict.fromkeys(n for n in (norm_entry(str(r)) for r in c.get("routes", [])) if n))
    p = config_path(c["name"])
    if p.exists():
        BACKUPS.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, BACKUPS / ("%s.%s.json" % (c["name"], dt.datetime.now().strftime("%Y%m%d-%H%M%S"))))
    atomic_write(p, json.dumps(c, indent=2) + "\n")


def delete_config(name: str) -> None:
    p = config_path(name)
    if p.exists():
        os.replace(p, p.with_suffix(".json.deleted"))


def find_config(key: str, configs: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    configs = load_configs() if configs is None else configs
    for c in configs:
        if key in (c["name"], c.get("nm_name"), c.get("nm_uuid")):
            return c
    low = key.lower()
    for c in configs:
        if low in (c["name"].lower(), str(c.get("nm_name", "")).lower()):
            return c
    return None


# ---------------------------------------------------------------- runtime state (what WE added)
def state_path(name: str) -> Path:
    return STATE / ("%s.json" % name)


def load_state(name: str) -> Dict[str, Any]:
    try:
        d = json.loads(state_path(name).read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(name: str, st: Dict[str, Any]) -> None:
    atomic_write(state_path(name), json.dumps(st, indent=2) + "\n")


def clear_state(name: str) -> None:
    try:
        state_path(name).unlink()
    except OSError:
        pass


# ======================================================================================
# 4. discovery: NetworkManager, interfaces, routes, foreign VPNs
# ======================================================================================
def nm_split(line: str) -> List[str]:
    """split an `nmcli -t` line on unescaped ':'"""
    out, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def nm_unescape(v: str) -> str:
    return re.sub(r"\\(.)", r"\1", v)


def parse_vpn_dict(v: str) -> Dict[str, str]:
    """'a = 1, b = x\\,y' -> {'a': '1', 'b': 'x,y'}"""
    out: Dict[str, str] = {}
    for part in re.split(r"(?<!\\),\s*", v.strip()):
        if "=" in part:
            k, val = part.split("=", 1)
            out[k.strip()] = val.strip().replace("\\,", ",")
    return out


@dataclass
class NMProfile:
    name: str
    uuid: str
    ctype: str              # vpn | wireguard
    kind: str = "nm-other"
    service: str = ""
    data: Dict[str, str] = field(default_factory=dict)
    user: str = ""
    never_default: bool = False
    active: bool = False
    state: str = ""         # activated | activating | ...
    secret_flags: Dict[str, int] = field(default_factory=dict)


SERVICE_KIND = {"openvpn": "nm-openvpn", "l2tp": "nm-l2tp"}


def nm_available() -> bool:
    return shutil.which("nmcli") is not None


def nm_profiles(details: bool = True) -> List[NMProfile]:
    if not nm_available():
        return []
    rc, out, _ = sh([NMCLI, "-t", "-f", "NAME,UUID,TYPE", "connection", "show"])
    if rc != 0:
        return []
    act = nm_active()
    profs = []
    for line in out.splitlines():
        f = nm_split(line)
        if len(f) < 3 or f[2] not in ("vpn", "wireguard"):
            continue
        p = NMProfile(name=f[0], uuid=f[1], ctype=f[2])
        p.kind = "nm-wireguard" if f[2] == "wireguard" else "nm-other"
        if p.uuid in act:
            p.state = act[p.uuid]
            p.active = p.state == "activated"
        if details:
            nm_fill(p)
        profs.append(p)
    return profs


def nm_fill(p: NMProfile) -> None:
    rc, out, _ = sh([NMCLI, "-g", "vpn.service-type,vpn.data,vpn.user-name,ipv4.never-default", "connection", "show", "uuid", p.uuid])
    if rc != 0:
        return
    lines = out.split("\n")
    get = lambda i: nm_unescape(lines[i]) if len(lines) > i else ""  # noqa: E731
    p.service = get(0)
    p.data = parse_vpn_dict(get(1))
    p.user = get(2) or p.data.get("user", "") or p.data.get("username", "")
    p.never_default = get(3).strip() == "yes"
    short = p.service.rsplit(".", 1)[-1] if p.service else ""
    if p.ctype == "vpn":
        p.kind = SERVICE_KIND.get(short, "nm-other")
    for k, v in p.data.items():
        if k.endswith("-flags") and k[:-6] in ("password", "cert-pass", "ipsec-psk", "Xauth password", "IPSec secret", "secret", "key-pass"):
            try:
                p.secret_flags[k[:-6]] = int(v)
            except ValueError:
                pass
    if p.kind == "nm-l2tp" and p.data.get("ipsec-enabled") == "yes" and "ipsec-psk" not in p.secret_flags:
        p.secret_flags["ipsec-psk"] = 0
    if p.kind == "nm-l2tp" or (p.kind == "nm-openvpn" and p.data.get("connection-type", "tls") in ("password", "password-tls")):
        p.secret_flags.setdefault("password", 0)   # a missing *-flags key means 0 (= stored in the system profile)


def nm_active() -> Dict[str, str]:
    rc, out, _ = sh([NMCLI, "-t", "-f", "UUID,TYPE,STATE", "connection", "show", "--active"])
    res = {}
    if rc == 0:
        for line in out.splitlines():
            f = nm_split(line)
            if len(f) >= 3:
                res[f[0]] = f[2]
    return res


def nm_secret_keys_stored(uuid: str) -> Tuple[Optional[set], str]:
    """names of secrets NM can hand out for this profile (never the values). None = could not read."""
    rc, out, err = sh([NMCLI, "-s", "-g", "vpn.secrets", "connection", "show", "uuid", uuid], timeout=10)
    if rc != 0:
        return None, err.strip()
    d = parse_vpn_dict(nm_unescape(out.strip()))
    return {k for k, v in d.items() if v}, ""


def nm_ip4(uuid: str) -> Tuple[List[str], str]:
    rc, out, _ = sh([NMCLI, "-g", "IP4.ADDRESS,IP4.GATEWAY", "connection", "show", "uuid", uuid])
    if rc != 0:
        return [], ""
    lines = out.split("\n")
    addrs = [a.strip().split("/")[0] for a in (lines[0] if lines else "").split("|") if a.strip()]
    gw = lines[1].strip() if len(lines) > 1 else ""
    return addrs, gw


# ---------------------------------------------------------------- interfaces
@dataclass
class Iface:
    name: str
    index: int
    kind: str          # tun | ppp | wireguard | tap | eth | other
    up: bool
    addrs: List[str] = field(default_factory=list)
    peer: str = ""


def iface_kind(name: str) -> str:
    base = Path("/sys/class/net") / name
    try:
        ue = (base / "uevent").read_text()
    except OSError:
        ue = ""
    if "DEVTYPE=wireguard" in ue:
        return "wireguard"
    try:
        t = int((base / "type").read_text().strip())
    except (OSError, ValueError):
        t = 0
    if t == 512:
        return "ppp"
    if (base / "tun_flags").exists():
        try:
            flags = int((base / "tun_flags").read_text().strip(), 16)
            return "tap" if flags & 0x0002 else "tun"
        except (OSError, ValueError):
            return "tun"
    if "DEVTYPE=bridge" in ue or name.startswith(("br-", "docker", "virbr", "veth", "mpqemubr")):
        return "bridge"
    if name == "lo":
        return "lo"
    if t == 1:
        return "eth"
    return "other"


def interfaces() -> Dict[str, Iface]:
    res: Dict[str, Iface] = {}
    rc, out, _ = sh([IP, "-o", "link", "show"])
    for line in out.splitlines():
        m = re.match(r"(\d+):\s+([^:@\s]+)[^:]*:\s+<([^>]*)>", line)
        if m:
            name = m.group(2)
            res[name] = Iface(name=name, index=int(m.group(1)), kind=iface_kind(name), up="UP" in m.group(3).split(","))
    rc, out, _ = sh([IP, "-o", "-4", "addr", "show"])
    for line in out.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)(?:\s+peer\s+([\d.]+))?", line)
        if m and m.group(1) in res:
            res[m.group(1)].addrs.append(m.group(2))
            if m.group(3):
                res[m.group(1)].peer = m.group(3)
    return res


TUNNEL_KINDS = ("tun", "tap", "ppp", "wireguard")


def iface_stats(name: str) -> Tuple[int, int]:
    base = Path("/sys/class/net") / name / "statistics"
    try:
        return int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
    except (OSError, ValueError):
        return 0, 0


# ---------------------------------------------------------------- routes
@dataclass
class RouteEntry:
    dst: str
    dev: str = ""
    via: str = ""
    table: str = "main"
    proto: str = ""
    raw: str = ""


def all_routes() -> List[RouteEntry]:
    rc, out, _ = sh([IP, "-o", "-4", "route", "show", "table", "all"])
    res = []
    for line in out.splitlines():
        tok = line.split()
        if not tok or tok[0] in ("broadcast", "local", "unreachable", "prohibit", "blackhole", "multicast", "anycast"):
            continue
        e = RouteEntry(dst=tok[0], raw=line)
        for k in ("dev", "via", "table", "proto"):
            if k in tok:
                i = tok.index(k)
                if i + 1 < len(tok):
                    setattr(e, k, tok[i + 1])
        res.append(e)
    return res


def route_get(dst: str) -> Tuple[str, str, str]:
    """(dev, via, err) for where the kernel sends dst right now"""
    try:
        net = ipaddress.ip_network(dst, strict=False)
        host = str(net.network_address if net.prefixlen >= 31 else net.network_address + 1)
    except ValueError:
        return "", "", "bad address"
    rc, out, err = sh([IP, "-o", "route", "get", host], timeout=5)
    if rc != 0:
        return "", "", err.strip()
    tok = out.split()
    dev = tok[tok.index("dev") + 1] if "dev" in tok else ""
    via = tok[tok.index("via") + 1] if "via" in tok else ""
    return dev, via, ""


def default_routes() -> List[RouteEntry]:
    return [r for r in all_routes() if r.dst == "default" and r.table in ("main", "")]


def policy_rules() -> List[str]:
    rc, out, _ = sh([IP, "-4", "rule", "show"])
    return out.splitlines() if rc == 0 else []


# ---------------------------------------------------------------- processes
@dataclass
class ProcInfo:
    pid: int
    ppid: int
    comm: str
    cmdline: str


def processes() -> List[ProcInfo]:
    res = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % d) as f:
                st = f.read()
            comm = st[st.index("(") + 1: st.rindex(")")]
            ppid = int(st[st.rindex(")") + 2:].split()[1])
            with open("/proc/%s/cmdline" % d, "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
            res.append(ProcInfo(int(d), ppid, comm, cmd))
        except (OSError, ValueError, IndexError):
            continue
    return res


def pid_alive(pid: Optional[int], needle: str = "") -> bool:
    if not pid:
        return False
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
        return needle in cmd if needle else True
    except OSError:
        return False


# ---------------------------------------------------------------- foreign VPNs
@dataclass
class Foreign:
    name: str
    state: str           # connected | disconnected | running | present | unknown
    detail: str = ""
    ifaces: List[str] = field(default_factory=list)
    owns_default: bool = False


FOREIGN_PROCS = {
    "windscribe": "Windscribe", "windscribeengine": "Windscribe", "windscribe-cli": "Windscribe",
    "expressvpnd": "ExpressVPN", "expressvpn-daemon": "ExpressVPN", "expressvpn": "ExpressVPN",
    "v2ray": "v2ray", "xray": "xray", "sing-box": "sing-box", "clash": "clash", "mihomo": "clash/mihomo",
    "clash-meta": "clash/mihomo", "hiddify": "Hiddify", "hiddifycli": "Hiddify", "nekoray": "NekoRay", "nekobox": "NekoBox",
    "v2raya": "v2rayA", "tun2socks": "tun2socks", "hysteria": "hysteria", "tailscaled": "Tailscale", "zerotier-one": "ZeroTier",
    "nordvpnd": "NordVPN", "protonvpn": "ProtonVPN", "mullvad-daemon": "Mullvad", "warp-svc": "Cloudflare WARP",
    "openconnect": "openconnect", "openfortivpn": "openfortivpn", "ssh": None,
}


def _tool_status(cmd: List[str], timeout: float = 6) -> List[str]:
    rc, out, err = sh(cmd, timeout=timeout)
    lines = []
    for l in (out + "\n" + err).splitlines():
        l = l.strip()
        if not l or l.startswith("{"):   # windscribe-cli prints JSON log lines first
            continue
        lines.append(re.sub(r"\x1b\[[0-9;]*m", "", l))
    return lines


def detect_foreign(own_ifaces: set, deep: bool = True) -> List[Foreign]:
    """other VPNs on this machine (not managed by us)"""
    res: Dict[str, Foreign] = {}
    ifs = interfaces()
    procs = processes()
    defaults = default_routes()
    def_devs = {r.dev for r in defaults}
    rules = policy_rules()
    tables = {r.table for r in all_routes()}

    # 1. vendor CLIs
    if deep and shutil.which("windscribe-cli"):
        ls = _tool_status(["windscribe-cli", "status"])
        conn = next((l for l in ls if l.lower().startswith(("connect state", "connected", "disconnected"))), "")
        state = "connected" if re.search(r"\bconnected\b", conn.lower()) and "dis" not in conn.lower() else "disconnected"
        if not conn and any("logged out" in l.lower() for l in ls):
            state = "disconnected"
        res["Windscribe"] = Foreign("Windscribe", state, " · ".join(ls[:4]))
    if deep and shutil.which("expressvpn"):
        ls = _tool_status(["expressvpn", "status"])
        state = "connected" if any(l.lower().startswith("connected") for l in ls) else "disconnected"
        res["ExpressVPN"] = Foreign("ExpressVPN", state, " · ".join(ls[:3]))
    if deep and shutil.which("nordvpn"):
        ls = _tool_status(["nordvpn", "status"])
        res["NordVPN"] = Foreign("NordVPN", "connected" if any("connected" in l.lower() and "dis" not in l.lower() for l in ls) else "disconnected", " · ".join(ls[:3]))
    if deep and shutil.which("mullvad"):
        ls = _tool_status(["mullvad", "status"])
        res["Mullvad"] = Foreign("Mullvad", "connected" if ls and ls[0].lower().startswith("connected") else "disconnected", " · ".join(ls[:2]))
    if deep and shutil.which("warp-cli"):
        ls = _tool_status(["warp-cli", "status"])
        res["Cloudflare WARP"] = Foreign("Cloudflare WARP", "connected" if any("connected" in l.lower() and "dis" not in l.lower() for l in ls) else "disconnected", " · ".join(ls[:2]))

    # 2. processes
    for p in procs:
        label = FOREIGN_PROCS.get(p.comm.lower())
        if label is None and p.comm.lower().startswith("expressvpn"):
            label = "ExpressVPN"
        if not label:
            continue
        f = res.setdefault(label, Foreign(label, "running"))
        if f.state == "unknown":
            f.state = "running"
        if not f.detail:
            f.detail = "process %s (pid %d)" % (p.comm, p.pid)
    # plain openvpn not started by NetworkManager
    for p in procs:
        if p.comm == "openvpn":
            parent = next((q for q in procs if q.pid == p.ppid), None)
            if parent and parent.comm.startswith("nm-openvpn"):
                continue
            m = re.search(r"--config\s+(\S+)", p.cmdline)
            res.setdefault("openvpn (cli)", Foreign("openvpn (cli)", "running", "pid %d %s" % (p.pid, Path(m.group(1)).name if m else "")))
    # sshuttle not ours
    our_pids = {load_state(c["name"]).get("pid") for c in load_configs() if c["kind"] == "sshuttle"}
    for p in procs:
        if "sshuttle" in p.cmdline and "--firewall" not in p.cmdline and p.comm.startswith(("python", "sshuttle")) and p.pid not in our_pids:
            if any(q.pid == p.ppid and "sshuttle" in q.cmdline for q in procs):
                continue
            res.setdefault("sshuttle (other)", Foreign("sshuttle (other)", "running", "pid %d" % p.pid))

    # 3. policy routing fingerprints
    if any("evpn" in r for r in rules) or any(t.startswith("evpn") for t in tables):
        f = res.setdefault("ExpressVPN", Foreign("ExpressVPN", "present", "policy rules (evpn* tables) installed"))
        if not f.detail:
            f.detail = "policy rules (evpn* tables) installed"
    if "windscribe" in tables or any("windscribe" in r for r in rules):
        f = res.setdefault("Windscribe", Foreign("Windscribe", "present"))
        f.detail = (f.detail + " · " if f.detail else "") + "routing table 'windscribe' present"

    # 4. tunnel interfaces we do not own
    for name, i in ifs.items():
        if i.kind not in TUNNEL_KINDS or name in own_ifaces:
            continue
        label = None
        low = name.lower()
        if "windscribe" in low or low.startswith("utun420"):
            label = "Windscribe"
        elif low.startswith(("xray", "v2ray")):
            label = "xray/v2ray"
        elif low.startswith(("sing", "tun-sing")):
            label = "sing-box"
        elif low.startswith(("clash", "meta", "mihomo")):
            label = "clash/mihomo"
        elif low.startswith("tailscale"):
            label = "Tailscale"
        elif low.startswith("wg") or i.kind == "wireguard":
            label = "WireGuard (%s)" % name
        elif low.startswith("nordlynx"):
            label = "NordVPN"
        else:
            label = "tunnel %s" % name
        f = res.setdefault(label, Foreign(label, "connected"))
        f.ifaces.append(name)
        if f.state in ("running", "present", "disconnected", "unknown"):
            f.state = "connected"
        if not f.detail:
            f.detail = "%s %s %s" % (i.kind, name, ",".join(i.addrs))
    for f in res.values():
        f.owns_default = any(d in def_devs for d in f.ifaces)
        if f.owns_default:
            f.detail = (f.detail + " · " if f.detail else "") + "owns the default route (full tunnel)"
    return sorted(res.values(), key=lambda f: (f.state != "connected", f.name))


# ======================================================================================
# 5. status / analysis of OUR VPNs
# ======================================================================================
@dataclass
class RouteHealth:
    dst: str
    dev: str
    via: str
    ok: bool
    note: str = ""
    src: str = ""        # the range / hostname entry this prefix came from ('' for plain IP/CIDR)
    owner: str = ""      # another of OUR VPNs that currently owns this shared prefix


@dataclass
class VpnStatus:
    name: str
    kind: str
    display: str
    configured: bool
    profile_ok: bool = True
    state: str = "down"          # up | degraded | partial | activating | down | missing
    iface: str = ""
    local_ip: str = ""
    gw: str = ""
    since: Optional[float] = None
    rx: int = 0
    tx: int = 0
    pid: Optional[int] = None
    routes: List[RouteHealth] = field(default_factory=list)
    routes_applied: bool = False
    autostart: bool = False
    message: str = ""
    nm: Optional[NMProfile] = None
    cfg: Optional[Dict[str, Any]] = None
    probes: List["ProbeResult"] = field(default_factory=list)

    @property
    def routes_ok(self) -> int:
        return sum(1 for r in self.routes if r.ok)

    @property
    def routes_bad(self) -> int:
        """not through this VPN and not owned by another of our VPNs either"""
        return sum(1 for r in self.routes if not r.ok and not r.owner)


UP_STATES = ("up", "partial", "degraded")


def _ownership_and_health(out: List[VpnStatus]) -> None:
    """shared prefixes: mark which of our VPNs owns them; then partial (routes lost) / degraded (probes failing)"""
    iface_owner = {s.iface: s.name for s in out if s.iface and s.state == "up"}
    ssh_up = {s.name for s in out if s.kind == "sshuttle" and s.state == "up"}
    claims: Dict[str, set] = collections.defaultdict(set)
    for s in out:
        for r in expand_routes((s.cfg or {}).get("routes", [])):
            claims[r].add(s.name)
    for s in out:
        for r in s.routes:
            others = claims.get(r.dst, set()) - {s.name}
            if not others:
                continue
            sh_owner = next((o for o in others if o in ssh_up), None)
            if sh_owner and s.kind != "sshuttle":      # sshuttle intercepts with iptables before routing applies
                r.ok, r.owner, r.note = False, sh_owner, "○ shared — sshuttle '%s' intercepts it" % sh_owner
            elif not r.ok and iface_owner.get(r.dev) in others:
                r.owner = iface_owner[r.dev]
                r.note = "○ shared — '%s' owns it now" % r.owner
    pint = float(load_settings().get("probe_interval", 15))
    for s in out:
        if s.state == "up" and s.kind != "sshuttle" and s.routes and s.routes_bad:
            s.state = "partial"
        if s.state in UP_STATES and s.cfg and s.cfg.get("probes"):
            want = set(s.cfg["probes"])
            s.probes = [x for x in load_probe_results(s.name) if x.target in want and now() - x.ts < max(90, 4 * pint)]
            if s.state == "up" and any(not x.ok for x in s.probes):
                s.state = "degraded"


def find_tunnel_iface(uuid: str, ifs: Optional[Dict[str, Iface]] = None) -> Tuple[str, str, str]:
    """(iface, local_ip, peer) of an active NM VPN, found by its IP4 address -- never GENERAL.IP-IFACE (that is the parent NIC)"""
    ifs = ifs if ifs is not None else interfaces()
    addrs, gw = nm_ip4(uuid)
    for a in addrs:
        for i in ifs.values():
            if a in i.addrs and i.kind in TUNNEL_KINDS:
                return i.name, a, i.peer or gw
    for a in addrs:
        for i in ifs.values():
            if a in i.addrs:
                return i.name, a, i.peer or gw
    return "", "", gw


def collect_status(with_routes: bool = True, profiles: Optional[List[NMProfile]] = None) -> List[VpnStatus]:
    configs = load_configs()
    profiles = profiles if profiles is not None else nm_profiles()
    ifs = interfaces()
    by_uuid = {p.uuid: p for p in profiles}
    by_name = {p.name: p for p in profiles}
    out: List[VpnStatus] = []
    used = set()
    for c in configs:
        st = load_state(c["name"])
        s = VpnStatus(name=c["name"], kind=c["kind"], display=c.get("nm_name") or c["name"], configured=True,
                      autostart=autostart_enabled(c["name"]) if shutil.which("systemctl") else bool(c.get("autostart")), cfg=c)
        if c.get("broken"):
            s.state, s.message = "missing", "config file is not valid JSON"
            out.append(s)
            continue
        if c["kind"] == "sshuttle":
            s.display = c.get("ssh_remote") or c["name"]
            pid = st.get("pid")
            if pid_alive(pid, "sshuttle"):
                s.state, s.pid, s.since = "up", pid, st.get("since")
                s.routes_applied = True
            elif st:
                s.state, s.message = "down", "sshuttle exited (see logs)"
        else:
            p = by_uuid.get(c.get("nm_uuid", "")) or by_name.get(c.get("nm_name", ""))
            if not p:
                s.state, s.profile_ok, s.message = "missing", False, "NetworkManager profile not found"
            else:
                used.add(p.uuid)
                s.nm, s.display = p, p.name
                if p.active:
                    s.state = "up"
                    s.iface, s.local_ip, peer = find_tunnel_iface(p.uuid, ifs)
                    s.gw = c.get("gateway") if c.get("gateway") not in (None, "", "auto") else peer
                    s.since = st.get("since")
                    s.routes_applied = bool(st.get("routes")) and st.get("iface") == s.iface
                elif p.state:
                    s.state = "activating"
        if s.iface:
            s.rx, s.tx = iface_stats(s.iface)
        if with_routes and c.get("routes"):
            srcs = route_sources(c["routes"])
            for r in expand_routes(c["routes"]):
                if s.state == "up" and c["kind"] == "sshuttle":
                    s.routes.append(RouteHealth(r, "sshuttle", "", True, "redirected by sshuttle (iptables)", srcs.get(r, "")))
                    continue
                dev, via, err = route_get(r)
                ok = s.state == "up" and bool(s.iface) and dev == s.iface
                note = err
                if s.state == "up" and not ok:
                    note = "goes via %s%s instead" % (dev or "?", (" (" + via + ")") if via else "")
                s.routes.append(RouteHealth(r, dev, via, ok, note, srcs.get(r, "")))
        out.append(s)
    _ownership_and_health(out)
    for p in profiles:
        if p.uuid in used:
            continue
        s = VpnStatus(name=slug(p.name), kind=p.kind, display=p.name, configured=False, nm=p,
                      state="up" if p.active else ("activating" if p.state else "down"), message="not managed yet (adopt it)")
        if p.active:
            s.iface, s.local_ip, s.gw = find_tunnel_iface(p.uuid, ifs)
            if s.iface:
                s.rx, s.tx = iface_stats(s.iface)
        out.append(s)
    return out


def own_ifaces(statuses: List[VpnStatus]) -> set:
    return {s.iface for s in statuses if s.iface}


def ping(host: str, timeout: int = 2) -> Optional[float]:
    if not host:
        return None
    rc, out, _ = sh(["ping", "-n", "-c", "1", "-W", str(timeout), host], timeout=timeout + 2)
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    return float(m.group(1)) if rc == 0 and m else None


# ======================================================================================
# 6. connect engine
# ======================================================================================
def _route_cmd(action: str, dst: str, dev: str, via: str = "") -> List[str]:
    cmd = [IP, "-4", "route", action, dst]
    if via:
        cmd += ["via", via]
    return cmd + ["dev", dev]


def clean_exclusions(routes: List[str], settings: Dict[str, Any], say: Say, keep_dev: str = "") -> None:
    """remove /32 (or exact) routes for our destinations from main/windscribe/... so ours can own them.
    Routes that already point at keep_dev are left alone."""
    tables = [t for t in settings.get("clean_tables", ["main"]) if t]
    present = {}
    for e in all_routes():
        dst = norm_route(e.dst) if e.dst != "default" else None
        if dst:
            present.setdefault(dst, []).append(e)
    for r in routes:
        for e in present.get(r, []):
            tbl = e.table or "main"
            if tbl not in tables or (keep_dev and e.dev == keep_dev and tbl == "main"):
                continue
            cmd = [IP, "-4", "route", "del", r, "table", tbl]
            if e.dev:
                cmd += ["dev", e.dev]
            rc, _, err = priv(cmd)
            say("removed existing route %s (table %s, dev %s)" % (short_route(r), tbl, e.dev or "-") if rc == 0 else
                "could not remove %s from table %s: %s" % (short_route(r), tbl, err.strip()), "INFO" if rc == 0 else "WARN")


def apply_routes(c: Dict[str, Any], iface: str, gw: str, settings: Dict[str, Any], say: Say) -> Dict[str, Any]:
    """add our split-tunnel routes; returns the state record of what we added"""
    routes = resolve_for_apply(c, say)
    clean_exclusions(routes, settings, say, keep_dev=iface)
    rc, _, err = priv([IP, "-4", "route", "del", "default", "dev", iface])
    if rc == 0:
        say("removed default route the VPN pushed through %s (split tunnel)" % iface, "WARN")
    added, rules, failed = [], [], 0
    for r in routes:
        rc, _, err = priv(_route_cmd("replace", r, iface, gw))
        if rc != 0 and gw:   # gateway not reachable on-link? fall back to a device route (fine for tun/ppp)
            rc2, _, err2 = priv(_route_cmd("replace", r, iface))
            if rc2 == 0:
                say("%s: gateway %s rejected (%s) -> device route on %s" % (short_route(r), gw, err.strip(), iface), "WARN")
                rc, err, used_gw = 0, "", ""
            else:
                used_gw = gw
        else:
            used_gw = gw
        if rc == 0:
            added.append({"dst": r, "dev": iface, "via": used_gw})
        else:
            failed += 1
            say("route %s failed: %s" % (short_route(r), err.strip()), "ERROR")
            continue
        if settings.get("policy_rules", True):
            priv([IP, "-4", "rule", "del", "to", r, "lookup", "main", "priority", str(RULE_PRIO)])
            rc, _, err = priv([IP, "-4", "rule", "add", "to", r, "lookup", "main", "priority", str(RULE_PRIO)])
            if rc == 0:
                rules.append(r)
    say("routes: %d added via %s%s, %d failed%s" % (len(added), iface, (" gw " + gw) if gw else "", failed,
                                                   (", %d policy rules" % len(rules)) if rules else ""), "OK" if not failed else "WARN")
    return {"routes": added, "rules": rules}


def resolve_for_apply(c: Dict[str, Any], say: Say) -> List[str]:
    """expand the route list for the kernel; hostnames are looked up fresh (falls back to the last known IPs)"""
    for h in host_entries(c.get("routes", [])):
        ips, err = resolve_host(h, max_age=0)
        if ips:
            say("%s → %s%s" % (h, ", ".join(ips), ("  (" + err + ")") if err else ""), "WARN" if err else "INFO")
        else:
            say("%s does not resolve (%s) — skipped" % (h, err), "WARN")
    return expand_routes(c.get("routes", []), resolve=False)


def remove_routes(name: str, say: Say) -> None:
    st = load_state(name)
    n = 0
    for r in st.get("routes", []):
        rc, _, err = priv(_route_cmd("del", r["dst"], r["dev"], r.get("via", "")))
        if rc != 0:
            rc, _, err = priv(_route_cmd("del", r["dst"], r["dev"]))
        n += rc == 0
    for r in st.get("rules", []):
        priv([IP, "-4", "rule", "del", "to", r, "lookup", "main", "priority", str(RULE_PRIO)])
    if st.get("routes") or st.get("rules"):
        say("removed %d route(s) and %d rule(s) we had added" % (n, len(st.get("rules", []))))
    handoff({r["dst"] for r in st.get("routes", [])} | set(st.get("rules", [])), name, say)


def handoff(dsts: set, leaving: str, say: Say) -> None:
    """IPs shared with another VPN that is still up go back to that VPN (its recorded routes/rules are restored)"""
    if not dsts:
        return
    ifs = interfaces()
    for other in sorted(c["name"] for c in load_configs()):   # only real VPN state files (not probes / dns cache)
        if other == leaving:
            continue
        ost = load_state(other)
        if not isinstance(ost, dict) or not ost.get("iface") or ost["iface"] not in ifs:
            continue
        back = 0
        for r in ost.get("routes", []):
            if r["dst"] in dsts:
                back += priv(_route_cmd("replace", r["dst"], r["dev"], r.get("via", "")))[0] == 0
        for r in ost.get("rules", []):
            if r in dsts:
                priv([IP, "-4", "rule", "add", "to", r, "lookup", "main", "priority", str(RULE_PRIO)])
        if back:
            say("handed %d shared route(s) back to '%s' (%s)" % (back, other, ost["iface"]), "OK")


def drop_stale(c: Dict[str, Any], old: Dict[str, Any], say: Say) -> None:
    """on re-apply: remove routes/rules we added earlier that are no longer in the config"""
    keep = set(expand_routes(c.get("routes", [])))
    n = 0
    for r in old.get("routes", []):
        if r["dst"] not in keep:
            rc, _, _ = priv(_route_cmd("del", r["dst"], r["dev"], r.get("via", "")))
            if rc != 0:
                rc, _, _ = priv(_route_cmd("del", r["dst"], r["dev"]))
            n += rc == 0
    gone = [r for r in old.get("rules", []) if r not in keep]
    for r in gone:
        priv([IP, "-4", "rule", "del", "to", r, "lookup", "main", "priority", str(RULE_PRIO)])
    if n or gone:
        say("removed %d route(s) / %d rule(s) no longer in the config" % (n, len(gone)))
        handoff({r["dst"] for r in old.get("routes", []) if r["dst"] not in keep} | set(gone), c["name"], say)


def iface_snapshot() -> Dict[str, int]:
    return {n: i.index for n, i in interfaces().items() if i.kind in TUNNEL_KINDS}


def connect(c: Dict[str, Any], settings: Dict[str, Any], out: Optional[Callable[[str], None]] = None) -> bool:
    say = Say(c["name"], out)
    say("=== up %s (%s) ===" % (c["name"], KIND_LABEL.get(c["kind"], c["kind"])))
    iss = [i for i in validate_config(c) if i.level == "error"]
    if iss:
        for i in iss:
            say("config: %s" % i.msg, "ERROR")
        return False
    ok = _connect_sshuttle(c, settings, say) if c["kind"] == "sshuttle" else _connect_nm(c, settings, say)
    st = load_state(c["name"])
    event(c["name"], "up" if ok else "fail", ("up · %s · %d route(s)" % (st.get("iface") or ("pid %s" % st.get("pid")), len(st.get("routes", [])) or
                                                                  len(expand_routes(c.get("routes", []))))) if ok else "connect failed (see log)")
    return ok


def _nm_ref(c: Dict[str, Any]) -> List[str]:
    return ["uuid", c["nm_uuid"]] if c.get("nm_uuid") else ["id", c["nm_name"]]


def _connect_nm(c: Dict[str, Any], settings: Dict[str, Any], say: Say) -> bool:
    profs = {p.uuid: p for p in nm_profiles()}
    p = profs.get(c.get("nm_uuid", "")) or next((q for q in profs.values() if q.name == c.get("nm_name")), None)
    if not p:
        say("NetworkManager profile %s not found" % (c.get("nm_name") or c.get("nm_uuid")), "ERROR")
        return False
    if c.get("never_default", True) and not p.never_default:
        rc, _, err = sh([NMCLI, "connection", "modify", "uuid", p.uuid, "ipv4.never-default", "yes", "ipv6.never-default", "yes"])
        say("set never-default=yes on the GUI profile (VPN never becomes the default route)" if rc == 0 else
            "could not set never-default: %s" % err.strip(), "INFO" if rc == 0 else "WARN")
    # stale tunnel from an earlier session of this VPN (L2TP leaves ppp0 behind as an 'external' device)
    old = load_state(c["name"])
    ifs = interfaces()
    if not p.active and old.get("iface") in ifs and ifs[old["iface"]].kind in TUNNEL_KINDS:
        say("stale interface %s from the last session is still there -> deleting it" % old["iface"], "WARN")
        priv([IP, "link", "delete", old["iface"]])
        time.sleep(1)
    if not p.active:
        timeout = int(settings.get("connect_timeout", 40))
        say("nmcli connection up %s (wait up to %ss; secrets come from the GUI profile / keyring) ..." % (p.name, timeout))
        rc, o, err = sh([NMCLI, "--wait", str(timeout), "connection", "up", "uuid", p.uuid], timeout=timeout + 10)
        for l in (o + err).strip().splitlines():
            say("nmcli: " + l, "INFO" if rc == 0 else "ERROR")
        if rc != 0:
            if "secrets" in (o + err).lower() or "password" in (o + err).lower():
                say("NetworkManager has no saved secret for this VPN -> use 'Secrets' (key s) to store them in the profile", "ERROR")
            for l in journal_lines(c, minutes=3, limit=12, errors_only=True):
                say("journal: " + l, "ERROR")
            return False
    else:
        say("already active in NetworkManager -> (re)applying routes")
    iface, local, peer = "", "", ""
    for _ in range(20):
        iface, local, peer = find_tunnel_iface(p.uuid)
        if iface:
            break
        time.sleep(1)
    if not iface:
        say("VPN is up but its tunnel interface could not be found (no IPv4 on a tun/ppp device)", "ERROR")
        return False
    gw = c.get("gateway") if c.get("gateway") not in (None, "", "auto") else (peer if peer and peer != local else "")
    say("tunnel %s  local %s  gateway %s" % (iface, local or "?", gw or "(device route)"), "OK")
    if p.active and old.get("iface") == iface:
        drop_stale(c, old, say)
    rec = apply_routes(c, iface, gw, settings, say)
    save_state(c["name"], {"iface": iface, "gw": gw, "local": local, "since": old.get("since") if p.active and old.get("iface") == iface else now(),
                           "uuid": p.uuid, **rec})
    if gw:
        ms = ping(gw)
        say("gateway %s answers ping (%.0f ms)" % (gw, ms) if ms is not None else "gateway %s does not answer ping (may be filtered)" % gw,
            "OK" if ms is not None else "WARN")
    return True


def _connect_sshuttle(c: Dict[str, Any], settings: Dict[str, Any], say: Say) -> bool:
    exe = which("sshuttle")
    if not exe:
        say("sshuttle is not installed (apt install sshuttle / pip install sshuttle)", "ERROR")
        return False
    st = load_state(c["name"])
    if pid_alive(st.get("pid"), "sshuttle"):
        say("already running (pid %s)" % st["pid"])
        return True
    routes = resolve_for_apply(c, say)
    clean_exclusions(routes, settings, say)
    cmd = [exe, "-r", c["ssh_remote"]] + shlex.split(c.get("ssh_args", "")) + routes
    say("starting: %s" % " ".join(shlex.quote(x) for x in cmd[:4]) + (" … (%d routes)" % len(routes)))
    LOGS.mkdir(parents=True, exist_ok=True)
    lf = log_path(c["name"])
    start_size = lf.stat().st_size if lf.exists() else 0
    with lf.open("a") as fh:
        proc = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True,
                                env=dict(os.environ, SSH_ASKPASS_REQUIRE="never"))
    save_state(c["name"], {"pid": proc.pid, "since": now(), "routes": [], "rules": [], "ssh_routes": routes})
    deadline = time.time() + int(settings.get("connect_timeout", 40))
    while time.time() < deadline:
        time.sleep(0.5)
        try:
            with lf.open() as f:
                f.seek(start_size)
                new = f.read()
        except OSError:
            new = ""
        if "Connected to server" in new or "Connected." in new:
            say("sshuttle connected (pid %d)" % proc.pid, "OK")
            return True
        if proc.poll() is not None:
            for l in new.strip().splitlines()[-12:]:
                say("sshuttle: " + l, "ERROR")
            if "sudo" in new.lower() and "password" in new.lower():
                say("sshuttle needs password-less sudo for its firewall helper -> run: mvm sudoers install", "ERROR")
            say("sshuttle exited with code %s" % proc.returncode, "ERROR")
            clear_state(c["name"])
            return False
    say("sshuttle still not connected after timeout -- leaving it running (pid %d), check the log" % proc.pid, "WARN")
    return True


def disconnect(c: Dict[str, Any], settings: Dict[str, Any], out: Optional[Callable[[str], None]] = None) -> bool:
    event(c["name"], "down", "stopped by you")
    return _disconnect(c, settings, out)


def _disconnect(c: Dict[str, Any], settings: Dict[str, Any], out: Optional[Callable[[str], None]] = None) -> bool:
    say = Say(c["name"], out)
    say("=== down %s ===" % c["name"])
    st = load_state(c["name"])
    if c["kind"] == "sshuttle":
        pid = st.get("pid")
        if pid_alive(pid, "sshuttle"):
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.25)
                if not pid_alive(pid, "sshuttle"):
                    break
            else:
                os.kill(pid, signal.SIGKILL)
                say("sshuttle did not stop on SIGTERM -> killed", "WARN")
            say("sshuttle stopped (its firewall rules are removed by sshuttle itself)", "OK")
        else:
            say("sshuttle was not running")
        clear_state(c["name"])
        return True
    remove_routes(c["name"], say)
    active = nm_active()
    uuid = c.get("nm_uuid") or st.get("uuid", "")
    if uuid in active or not uuid:
        rc, o, err = sh([NMCLI, "connection", "down"] + _nm_ref(c), timeout=30)
        say("nmcli: " + (o + err).strip().replace("\n", " "), "OK" if rc == 0 else "WARN")
    else:
        say("not active in NetworkManager")
    if st.get("iface"):
        for _ in range(8):
            if st["iface"] not in interfaces():
                break
            time.sleep(1)
        else:
            say("%s survived 'nmcli down' (L2TP pppd leftover) -> deleting the link" % st["iface"], "WARN")
            priv([IP, "link", "delete", st["iface"]])
    clear_state(c["name"])
    return True


def dns_changed(c: Dict[str, Any]) -> Optional[Tuple[set, set]]:
    """hostnames in the route list re-resolved (respecting dns_refresh). Returns (applied, wanted) if they differ."""
    hosts = host_entries(c.get("routes", []))
    st = load_state(c["name"])
    if not hosts or not st:
        return None
    for h in hosts:
        resolve_host(h)
    applied = set(st.get("ssh_routes") or [r["dst"] for r in st.get("routes", [])])
    wanted = set(expand_routes(c.get("routes", [])))
    return (applied, wanted) if applied != wanted and wanted else None


def probe_round(statuses: List[VpnStatus], timeout: float = 4) -> Dict[str, List[ProbeResult]]:
    """run the health probes of every VPN that is up; results are saved to state/<vpn>.probes.json"""
    out: Dict[str, List[ProbeResult]] = {}
    for s in statuses:
        if s.cfg and s.cfg.get("probes") and s.state in UP_STATES:
            out[s.name] = run_probes(list(s.cfg["probes"]), timeout)
            save_probe_results(s.name, out[s.name])
    return out


def connect_with_retries(c: Dict[str, Any], settings: Dict[str, Any], retries: int, out: Optional[Callable[[str], None]] = None) -> bool:
    for attempt in range(1, retries + 2):
        if connect(c, settings, out):
            return True
        if attempt <= retries:
            Say(c["name"], out)("attempt %d failed, retrying in 15s" % attempt, "WARN")
            time.sleep(15)
    return False


# ======================================================================================
# 7. journal / logs
# ======================================================================================
JOURNAL_IDS = ["NetworkManager", "nm-openvpn", "nm-l2tp-service", "pppd", "xl2tpd", "charon", "ipsec", "pluto", "nm-dispatcher", "sshuttle"]
ERR_RX = re.compile(r"error|fail|denied|timeout|timed out|refused|unreachable|AUTH_FAILED|no secrets|cannot|could not|unable|LCP terminated|bad", re.I)


def journal_lines(c: Dict[str, Any], minutes: int = 180, limit: int = 300, errors_only: bool = False) -> List[str]:
    if not shutil.which("journalctl"):
        return []
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", "-%dmin" % minutes, "-n", "4000"]
    for t in JOURNAL_IDS:
        cmd += ["-t", t]
    rc, out, _ = sh(cmd, timeout=15)
    if rc != 0:
        return []
    keys = [k for k in (c.get("nm_name"), c.get("nm_uuid"), c.get("name")) if k]
    kind_ids = {"nm-openvpn": ("nm-openvpn",), "nm-l2tp": ("nm-l2tp", "pppd", "xl2tpd", "charon", "ipsec", "pluto"),
                "sshuttle": ("sshuttle",)}.get(c.get("kind", ""), ())
    res = []
    for l in out.splitlines():
        if any(k in l for k in keys) or any((" %s[" % i) in l or (" %s:" % i) in l for i in kind_ids):
            if errors_only and not ERR_RX.search(l):
                continue
            res.append(l)
    return res[-limit:]


def tail_file(p: Path, n: int = 300) -> List[str]:
    try:
        with p.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 256 * 1024))
            return f.read().decode(errors="replace").splitlines()[-n:]
    except OSError:
        return []


# ======================================================================================
# 8. sudoers + autostart
# ======================================================================================
def sshuttle_sudo_alias() -> Optional[str]:
    exe = which("sshuttle")
    if not exe:
        return None
    rc, out, _ = sh([exe, "--sudoers-no-modify"], timeout=15)
    m = re.search(r"^Cmnd_Alias\s+\w+\s*=\s*(.+)$", out, re.M)
    return m.group(1).strip() if m else None


def sudoers_text(user: Optional[str] = None) -> str:
    user = user or getpass.getuser()
    ipx = os.path.realpath(IP)
    cmds = ["%s route *" % IP, "%s -4 route *" % IP, "%s -4 rule *" % IP, "%s link delete *" % IP]
    if ipx != IP:
        cmds += ["%s route *" % ipx, "%s -4 route *" % ipx, "%s -4 rule *" % ipx, "%s link delete *" % ipx]
    lines = ["# managed by multi-vpn-manager (mvm.py) -- password-less routing for split-tunnel VPNs",
             "# remove with: sudo rm %s" % SUDOERS_FILE,
             "Cmnd_Alias MVM_NET = " + ", ".join(cmds),
             "%s ALL=(root) NOPASSWD: MVM_NET" % user]
    sa = sshuttle_sudo_alias()
    if sa:
        lines += ["# sshuttle's own firewall helper (as generated by `sshuttle --sudoers-no-modify`)",
                  "Cmnd_Alias MVM_SSHUTTLE = " + sa,
                  "%s ALL=(root) NOPASSWD: MVM_SSHUTTLE" % user]
    return "\n".join(lines) + "\n"


def sudoers_ok() -> Tuple[bool, str]:
    if os.geteuid() == 0:
        return True, "running as root"
    rc, _, err = sh(["sudo", "-n", IP, "-4", "route", "show", "table", "main"], timeout=8)
    if rc == 0:
        return True, "password-less sudo for ip works"
    return False, (err.strip().splitlines() or ["sudo needs a password"])[0]


def sshuttle_sudo_ok() -> Tuple[bool, str]:
    sa = sshuttle_sudo_alias()
    if not sa:
        return False, "sshuttle not installed"
    probe = shlex.split(sa.replace("*", "--firewall"))
    rc, out, err = sh(["sudo", "-n", "-l"] + probe, timeout=8)
    return rc == 0, ("allowed" if rc == 0 else (err.strip() or "not allowed without password"))


def install_sudoers(interactive_sudo: bool = True) -> Tuple[bool, str]:
    text = sudoers_text()
    with tempfile.NamedTemporaryFile("w", delete=False, prefix="mvm-sudoers-") as f:
        f.write(text)
        tmp = f.name
    try:
        sudo = ["sudo"] if interactive_sudo else ["sudo", "-n"]
        r = subprocess.run(sudo + ["visudo", "-cf", tmp])
        if r.returncode != 0:
            return False, "visudo rejected the generated file (%s)" % tmp
        r = subprocess.run(sudo + ["install", "-m", "0440", "-o", "root", "-g", "root", tmp, SUDOERS_FILE])
        if r.returncode != 0:
            return False, "could not install %s" % SUDOERS_FILE
        return True, "installed %s" % SUDOERS_FILE
    finally:
        os.unlink(tmp)


UNIT_DIR = Path.home() / ".config/systemd/user"
UNIT_NAME = "multi-vpn-manager@.service"


def unit_text() -> str:
    py = str(venv_python()) if venv_python().exists() else sys.executable
    me = str(Path(__file__).resolve())
    return """[Unit]
Description=Multi-VPN Manager: %%i
After=graphical-session.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sleep 8
ExecStart=%s %s up %%i --retries 4
ExecStop=%s %s down %%i
TimeoutStartSec=600

[Install]
WantedBy=default.target
""" % (py, me, py, me)


def set_autostart(name: str, on: bool) -> Tuple[bool, str]:
    if not shutil.which("systemctl"):
        return False, "systemctl not found (no systemd user session)"
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(UNIT_DIR / UNIT_NAME, unit_text())
    sh(["systemctl", "--user", "daemon-reload"])
    inst = "multi-vpn-manager@%s.service" % name
    rc, out, err = sh(["systemctl", "--user", "enable" if on else "disable", inst])
    c = find_config(name)
    if c and rc == 0:
        c["autostart"] = on
        save_config(c)
    return rc == 0, (out + err).strip() or ("enabled" if on else "disabled")


def autostart_enabled(name: str) -> bool:
    rc, out, _ = sh(["systemctl", "--user", "is-enabled", "multi-vpn-manager@%s.service" % name], timeout=5)
    return out.strip() == "enabled"


# ======================================================================================
# 9. secrets (stored in the NM profile; values never logged)
# ======================================================================================
def nm_escape_secret(v: str) -> str:
    return v.replace("\\", "\\\\").replace(",", "\\,")


def nm_set_secrets(uuid: str, secrets: Dict[str, str], use_sudo: str = "auto") -> Tuple[bool, str]:
    """store secrets in the system profile (flags=0). All keys are written in ONE call:
    `vpn.secrets` replaces the whole map, so writing them one by one erases the previous one."""
    if not secrets:
        return False, "nothing to store"
    existing: Dict[str, str] = {}
    rc, out, _ = sh([NMCLI, "-s", "-g", "vpn.secrets", "connection", "show", "uuid", uuid], timeout=10)
    if rc == 0:
        existing = parse_vpn_dict(nm_unescape(out.strip()))
    merged = {k: v for k, v in existing.items() if v}
    merged.update(secrets)
    args = []
    for k in secrets:
        args += ["+vpn.data", "%s-flags=0" % k]
    args += ["vpn.secrets", ",".join("%s=%s" % (k, nm_escape_secret(v)) for k, v in merged.items())]
    base = [NMCLI, "connection", "modify", "uuid", uuid] + args
    if use_sudo in ("auto", "no"):
        rc, out, err = sh(base, timeout=20)
        if rc == 0:
            return True, "stored %s" % ", ".join(sorted(secrets))
        if use_sudo == "no":
            return False, err.strip()
    if use_sudo == "interactive":
        r = subprocess.run(["sudo"] + base, capture_output=True, text=True)
        return r.returncode == 0, (r.stderr.strip() or "stored %s" % ", ".join(sorted(secrets)))
    rc, out, err = sh(["sudo", "-n"] + base, timeout=20)
    return rc == 0, (err.strip() or "stored %s" % ", ".join(sorted(secrets)))


SECRET_LABEL = {"password": "VPN password", "cert-pass": "private key passphrase", "ipsec-psk": "IPsec pre-shared key",
                "Xauth password": "XAuth password", "IPSec secret": "IPsec secret (group password)", "key-pass": "key passphrase"}
FLAG_TEXT = {0: "saved in profile", 1: "desktop keyring", 2: "always ask", 4: "not required"}


# ======================================================================================
# 9b. health probes · events · notifications · export / import
# ======================================================================================
def parse_probe(t: str) -> Optional[Tuple[str, str, int, str]]:
    """'host:port' | 'tcp:host:port' -> tcp · 'http(s)://…' -> http · 'ping:host' | bare IP/host -> ping.
    Returns (kind, host, port, url) or None."""
    t = (t or "").strip()
    if not t:
        return None
    if re.match(r"https?://", t, re.I):
        from urllib.parse import urlparse
        u = urlparse(t)
        if not u.hostname:
            return None
        return "http", u.hostname, u.port or (443 if u.scheme.lower() == "https" else 80), t
    if t.lower().startswith("ping:"):
        h = t[5:].strip()
        return ("ping", h, 0, "") if h and (is_host(h) or _is_ip(h)) else None
    if t.lower().startswith("tcp:"):
        t = t[4:]
    m = re.fullmatch(r"\[?([A-Za-z0-9_.-]+)\]?:(\d{1,5})", t)
    if m and 0 < int(m.group(2)) < 65536 and (is_host(m.group(1)) or _is_ip(m.group(1))):
        return "tcp", m.group(1), int(m.group(2)), ""
    if is_host(t) or _is_ip(t):
        return "ping", t, 0, ""
    return None


def _is_ip(x: str) -> bool:
    try:
        ipaddress.IPv4Address(x)
        return True
    except ValueError:
        return False


@dataclass
class ProbeResult:
    target: str
    kind: str
    ok: bool
    ms: Optional[float] = None
    detail: str = ""
    ts: float = 0.0


def run_probe(target: str, timeout: float = 4) -> ProbeResult:
    pp = parse_probe(target)
    if not pp:
        return ProbeResult(target, "?", False, None, "invalid probe", now())
    kind, host, port, url = pp
    t0 = time.monotonic()
    if kind == "tcp":
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
            return ProbeResult(target, kind, True, (time.monotonic() - t0) * 1000, "TCP open", now())
        except OSError as e:
            return ProbeResult(target, kind, False, None, (e.strerror or str(e))[:80], now())
    if kind == "http":
        import ssl
        import urllib.error
        import urllib.request
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # internal services often use self-signed certs
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "multi-vpn-manager-probe"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        except (urllib.error.URLError, OSError, ValueError) as e:
            reason = getattr(e, "reason", e)
            return ProbeResult(target, kind, False, None, str(reason)[:80], now())
        ms = (time.monotonic() - t0) * 1000
        return ProbeResult(target, kind, code < 500, ms, "HTTP %d" % code, now())
    ms = ping(host, timeout=max(1, int(timeout)))
    return ProbeResult(target, kind, ms is not None, ms, "ping %s" % ("%.0f ms" % ms if ms is not None else "no reply"), now())


def run_probes(targets: List[str], timeout: float = 4) -> List[ProbeResult]:
    res: List[Optional[ProbeResult]] = [None] * len(targets)

    def one(i: int, t: str) -> None:
        res[i] = run_probe(t, timeout)
    ths = [threading.Thread(target=one, args=(i, t), daemon=True) for i, t in enumerate(targets)]
    for th in ths:
        th.start()
    for th in ths:
        th.join(timeout + 3)
    return [r or ProbeResult(t, "?", False, None, "timed out", now()) for r, t in zip(res, targets)]


def probe_path(name: str) -> Path:
    return STATE / ("%s.probes.json" % name)


def save_probe_results(name: str, results: List[ProbeResult]) -> None:
    try:
        atomic_write(probe_path(name), json.dumps([r.__dict__ for r in results], indent=1))
    except OSError:
        pass


def load_probe_results(name: str) -> List[ProbeResult]:
    try:
        return [ProbeResult(**d) for d in json.loads(probe_path(name).read_text())]
    except (OSError, ValueError, TypeError):
        return []


# ---------------------------------------------------------------- event timeline
EVENTS_FILE = STATE / "events.jsonl"
EVENT_ICON = {"up": ("▲", C_GREEN), "down": ("▼", C_MUTED), "fail": ("✖", C_RED), "dropped": ("▼", C_RED), "routes": ("⇢", C_CYAN),
              "lost": ("⚠", C_ORANGE), "recovered": ("✔", C_GREEN), "probe": ("◍", C_ORANGE), "dns": ("⌂", C_BLUE),
              "config": ("✎", C_PURPLE), "info": ("•", C_BLUE)}


def event(vpn: str, kind: str, msg: str) -> None:
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        with _log_lock:
            with EVENTS_FILE.open("a") as f:
                f.write(json.dumps({"ts": now(), "vpn": vpn, "kind": kind, "msg": msg}) + "\n")
            if EVENTS_FILE.stat().st_size > 400_000:   # keep the newest ~half
                lines = EVENTS_FILE.read_text().splitlines()
                atomic_write(EVENTS_FILE, "\n".join(lines[len(lines) // 2:]) + "\n")
    except OSError:
        pass


def load_events(vpn: Optional[str] = None, n: int = 30) -> List[Dict[str, Any]]:
    out = []
    for l in tail_file(EVENTS_FILE, 3000):
        try:
            e = json.loads(l)
        except ValueError:
            continue
        if vpn is None or e.get("vpn") == vpn:
            out.append(e)
    return out[-n:]


def human_ago(ts: Optional[float]) -> str:
    if not ts:
        return "-"
    d = now() - ts
    if d < 60:
        return "%ds ago" % d
    if d < 3600:
        return "%dm ago" % (d // 60)
    if d < 86400:
        return "%dh ago" % (d // 3600)
    return dt.datetime.fromtimestamp(ts).strftime("%b %d %H:%M")


# ---------------------------------------------------------------- desktop notifications
def desktop_notify(title: str, body: str, urgency: str = "normal", vpn: Optional[str] = None) -> bool:
    """notify-send, if enabled globally and for this VPN"""
    if not load_settings().get("notifications", True) or not shutil.which("notify-send"):
        return False
    if vpn:
        c = find_config(vpn)
        if c is not None and not c.get("notify", True):
            return False
    cmd = ["notify-send", "-a", "Multi-VPN Manager", "-u", urgency]
    icon = BASE / "mvm.svg"
    if icon.exists():
        cmd += ["-i", str(icon)]
    return sh(cmd + [title, body], timeout=5)[0] == 0


# ---------------------------------------------------------------- export / import
EXPORT_FORMAT = "multi-vpn-manager/1"


def export_bundle(names: Optional[List[str]] = None, strip_routes: bool = False, strip_hosts: bool = False) -> Dict[str, Any]:
    """configs only — never secrets (they live in NetworkManager). Machine-specific fields are dropped."""
    vpns = []
    for c in load_configs():
        if c.get("broken") or (names and c["name"] not in names):
            continue
        e = {k: v for k, v in c.items() if k not in ("nm_uuid", "autostart", "broken")}
        if strip_routes:
            e["routes"], e["probes"] = [], []
        if strip_hosts:
            e["ssh_remote"], e["probes"] = "", []
            e["routes"] = [r for r in e.get("routes", []) if not is_host(str(r))]
        vpns.append(e)
    return {"format": EXPORT_FORMAT, "exported": dt.datetime.now().isoformat(timespec="seconds"), "version": VERSION,
            "stripped": {"routes": strip_routes, "hosts": strip_hosts}, "vpns": vpns}


def import_bundle(data: Dict[str, Any], overwrite: bool = False) -> List[Tuple[str, str]]:
    """returns [(name, what happened)]; links NM VPNs to local GUI profiles by name"""
    if not isinstance(data, dict) or data.get("format") != EXPORT_FORMAT or not isinstance(data.get("vpns"), list):
        raise ValueError("not a multi-vpn-manager export (format %r)" % (data.get("format") if isinstance(data, dict) else None))
    profs = {p.name: p for p in nm_profiles(details=False)}
    existing = {c["name"] for c in load_configs()}
    res = []
    for e in data["vpns"]:
        if not isinstance(e, dict) or not e.get("name") or e.get("kind") not in KINDS:
            res.append((str(e.get("name") if isinstance(e, dict) else "?"), "skipped: invalid entry"))
            continue
        name = slug(str(e["name"]))
        if name in existing and not overwrite:
            res.append((name, "skipped: already exists (use overwrite)"))
            continue
        c = default_config(name, e["kind"])
        c.update({k: v for k, v in e.items() if k in c and k not in ("nm_uuid", "autostart")})
        c["name"] = name
        note = ""
        if c["kind"] != "sshuttle":
            p = profs.get(c.get("nm_name", ""))
            if p:
                c["nm_uuid"] = p.uuid
                note = "linked to GUI profile '%s'" % p.name
            else:
                note = "GUI profile '%s' not on this machine — import the VPN in NetworkManager, then it links by name" % c.get("nm_name")
        errs = [i.msg for i in validate_config(c) if i.level == "error" and i.where != "nm"]
        if errs:
            res.append((name, "skipped: " + errs[0]))
            continue
        save_config(c)
        event(name, "config", "imported from bundle")
        res.append((name, ("replaced" if name in existing else "imported") + ("; " + note if note else "")))
    return res


# ======================================================================================
# 10. doctor (troubleshooting)
# ======================================================================================
@dataclass
class Check:
    group: str
    title: str
    status: str            # ok | warn | fail | info
    detail: str = ""
    hint: str = ""
    fix: str = ""          # fix id: sudoers | never_default:<vpn> | apply:<vpn> | secrets:<vpn> | reconnect:<vpn> | down:<vpn>


NM_PLUGIN_PKG = {"nm-openvpn": "network-manager-openvpn-gnome", "nm-l2tp": "network-manager-l2tp-gnome"}


def nm_plugin_installed(service: str) -> bool:
    for d in ("/usr/lib/NetworkManager/VPN", "/etc/NetworkManager/VPN", "/usr/lib64/NetworkManager/VPN"):
        try:
            for f in Path(d).glob("*.name"):
                if ("service=%s" % service) in f.read_text().replace(" ", ""):
                    return True
        except OSError:
            pass
    return False


def _tcp_ok(host: str, port: int, timeout: float = 4) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "TCP %s:%d open" % (host, port)
    except OSError as e:
        return False, "TCP %s:%d: %s" % (host, port, e.strerror or e)


def openvpn_remotes(data: Dict[str, str]) -> List[Tuple[str, int, str]]:
    res = []
    for item in re.split(r"[,\s]+", data.get("remote", "")):
        if not item:
            continue
        parts = item.split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else int(data.get("port", "1194") or 1194)
        proto = parts[2] if len(parts) > 2 else ("tcp" if data.get("proto-tcp") == "yes" else "udp")
        res.append((host, port, proto))
    return res


def ssh_target(remote: str) -> List[str]:
    m = re.fullmatch(r"(.+?):(\d+)", remote)
    return ["-p", m.group(2), m.group(1)] if m else [remote]


def run_doctor(settings: Dict[str, Any], only: Optional[str] = None, deep: bool = False) -> List[Check]:
    ck: List[Check] = []
    add = lambda *a, **k: ck.append(Check(*a, **k))  # noqa: E731
    configs = load_configs()
    if only:
        c0 = find_config(only, configs)
        configs_sel = [c0] if c0 else []
        if not c0:
            add("system", "VPN '%s'" % only, "fail", "no such managed VPN", "mvm list  (adopt it first: mvm adopt <name>)")
    else:
        configs_sel = configs

    # ---- system
    g = "system"
    if not only:
        add(g, "user", "ok" if os.geteuid() != 0 else "fail", getpass.getuser(),
            "" if os.geteuid() != 0 else "do not run with sudo: NetworkManager secrets live in your desktop session")
        add(g, "python", "ok" if sys.version_info >= (3, 10) else "fail", sys.version.split()[0], "" if sys.version_info >= (3, 10) else "needs Python 3.10+")
        have = can_import("textual") and can_import("rich")
        if not have and venv_python().exists():
            have = sh([str(venv_python()), "-c", "import textual, rich"])[0] == 0
        add(g, "TUI packages", "ok" if have else "warn", "textual + rich available" + (" (in .venv)" if not can_import("textual") and have else "")
            if have else "missing (CLI still works)", "" if have else "python3 mvm.py bootstrap")
    if not nm_available():
        add(g, "NetworkManager (nmcli)", "fail", "nmcli not found", "sudo apt install network-manager")
    else:
        rc, out, err = sh([NMCLI, "-t", "-f", "RUNNING,STATE", "general", "status"])
        add(g, "NetworkManager", "ok" if rc == 0 and out.startswith("running") else "fail", out.strip() or err.strip(),
            "" if rc == 0 else "sudo systemctl start NetworkManager")
    ok, msg = sudoers_ok()
    add(g, "password-less routing (sudoers)", "ok" if ok else "fail", msg,
        "" if ok else "mvm sudoers install   (one-time; allows only `ip route/rule/link delete` + sshuttle's helper)", fix="" if ok else "sudoers")
    if any(c["kind"] == "sshuttle" for c in configs_sel):
        if not which("sshuttle"):
            add(g, "sshuttle", "fail", "not installed", "sudo apt install sshuttle")
        else:
            ok, msg = sshuttle_sudo_ok()
            add(g, "sshuttle firewall helper sudo", "ok" if ok else "fail", msg, "" if ok else "mvm sudoers install", fix="" if ok else "sudoers")
    for kind in sorted({c["kind"] for c in configs_sel if c["kind"] in NM_PLUGIN_PKG}):
        svc = "org.freedesktop.NetworkManager.%s" % kind.split("-", 1)[1]
        inst = nm_plugin_installed(svc)
        add(g, "NM plugin for %s" % KIND_LABEL[kind], "ok" if inst else "fail", svc if inst else "plugin not installed",
            "" if inst else "sudo apt install %s" % NM_PLUGIN_PKG[kind])
    if not only:
        rc, out, _ = sh(["journalctl", "--no-pager", "-n", "1", "-t", "NetworkManager"], timeout=8)
        add(g, "journal access", "ok" if rc == 0 and out.strip() and "No journal" not in out else "warn",
            "can read NetworkManager logs" if rc == 0 and out.strip() else "cannot read the system journal",
            "" if rc == 0 and out.strip() else "sudo usermod -aG systemd-journal %s  (log out/in)" % getpass.getuser())

    statuses = collect_status(True)
    st_by = {s.name: s for s in statuses}
    # ---- foreign VPNs
    if not only:
        fs = detect_foreign(own_ifaces(statuses), deep=True)
        if not fs:
            add("other VPNs", "none detected", "ok", "no Windscribe / ExpressVPN / v2ray / WireGuard / foreign tunnels")
        for f in fs:
            add("other VPNs", f.name, "warn" if f.owns_default else "info", "%s — %s" % (f.state, f.detail),
                "our /32 routes + `lookup main` rules (prio %d) take precedence; if an IP still leaks, add that VPN's table to clean_tables in Settings" % RULE_PRIO
                if f.owns_default else "")

    # ---- per VPN
    for c in configs_sel:
        g = "vpn: " + c["name"]
        s = st_by.get(c["name"])
        if c.get("broken"):
            add(g, "config file", "fail", "invalid JSON", "fix or delete %s" % config_path(c["name"]))
            continue
        for i in validate_config(c, configs):
            add(g, "config: " + (i.where or "general"), "fail" if i.level == "error" else "warn", i.msg)
        if c["kind"] == "sshuttle":
            if deep and which("ssh"):
                tgt = ssh_target(c["ssh_remote"])
                rc, out, err = sh(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new"] + tgt +
                                  ["command -v python3 || command -v python"], timeout=20)
                if rc == 0 and out.strip():
                    add(g, "ssh key login", "ok", "logged in without a password")
                    add(g, "python on remote", "ok", out.strip().splitlines()[-1])
                elif rc == 0:
                    add(g, "ssh key login", "ok", "logged in without a password")
                    add(g, "python on remote", "fail", "no python on the server", "sshuttle needs python3 on the remote host")
                else:
                    add(g, "ssh key login", "fail", (err.strip().splitlines() or ["failed"])[-1],
                        "ssh-copy-id %s   (sshuttle uses your SSH keys / agent)" % " ".join(tgt))
            elif not deep:
                add(g, "ssh key login", "info", "not tested (quick mode)", "run a deep check")
        else:
            p = s.nm if s else None
            if not p:
                add(g, "GUI profile", "fail", "NetworkManager profile '%s' not found" % (c.get("nm_name") or c.get("nm_uuid")),
                    "re-adopt: mvm adopt <profile name> --name %s" % c["name"])
                continue
            add(g, "GUI profile", "ok", "%s · %s · user %s" % (p.name, KIND_LABEL.get(p.kind, p.kind), p.user or "-"))
            if p.service and not nm_plugin_installed(p.service):
                add(g, "plugin", "fail", "%s not installed" % p.service, "install the NetworkManager plugin for this VPN type")
            if c.get("never_default", True):
                add(g, "never-default", "ok" if p.never_default else "warn",
                    "VPN can never become the default route" if p.never_default else "profile may take over the default route (full tunnel)",
                    "" if p.never_default else "fix sets ipv4/ipv6.never-default=yes on the profile", fix="" if p.never_default else "never_default:" + c["name"])
            stored, serr = nm_secret_keys_stored(p.uuid) if p.secret_flags else (set(), "")
            for key, flag in sorted(p.secret_flags.items()):
                lab = SECRET_LABEL.get(key, key)
                if flag & 4:
                    add(g, "secret: " + lab, "ok", "not required")
                elif flag & 2:
                    add(g, "secret: " + lab, "warn", "set to 'always ask' -> prompts every time",
                        "store it (key s) so up/autostart work unattended", fix="secrets:" + c["name"])
                elif stored is None:
                    add(g, "secret: " + lab, "info", "%s (could not read: %s)" % (FLAG_TEXT.get(flag, flag), serr[:60]))
                elif key in stored:
                    add(g, "secret: " + lab, "ok", "%s ✔ stored" % FLAG_TEXT.get(flag, flag))
                else:
                    add(g, "secret: " + lab, "fail" if flag == 0 else "warn",
                        "%s but NOT stored -> NetworkManager will prompt" % FLAG_TEXT.get(flag, flag),
                        "store it (key s): written into the profile, all secrets in one call", fix="secrets:" + c["name"])
            if p.kind == "nm-openvpn":
                for k in ("ca", "cert", "key", "ta", "tls-crypt"):
                    f = p.data.get(k)
                    if f:
                        okf = os.access(f, os.R_OK)
                        add(g, "file: " + k, "ok" if okf else "fail", f, "" if okf else "file missing/unreadable -> re-import the .ovpn in the GUI")
                if deep:
                    for host, port, proto in openvpn_remotes(p.data)[:3]:
                        if proto.startswith("tcp"):
                            ok, msg = _tcp_ok(host, port)
                            add(g, "server reachable", "ok" if ok else "fail", msg, "" if ok else "server down, blocked, or another VPN is filtering it")
                        else:
                            ms = ping(host)
                            add(g, "server reachable", "ok" if ms is not None else "warn",
                                "UDP %s:%d (ping %s)" % (host, port, "%.0f ms" % ms if ms is not None else "no reply"), "UDP can't be probed; ping may be filtered")
            if p.kind == "nm-l2tp" and deep:
                host = p.data.get("gateway", "")
                if host:
                    ms = ping(host)
                    add(g, "server reachable", "ok" if ms is not None else "warn", "%s (ping %s)" % (host, "%.0f ms" % ms if ms is not None else "no reply"),
                        "" if ms is not None else "UDP 500/4500/1701 can't be probed; ping may be filtered")
        # runtime
        if s:
            if s.state in UP_STATES:
                add(g, "tunnel", "ok", "%s up since %s%s" % (s.iface or ("pid %s" % s.pid), human_dur(now() - s.since) if s.since else "?",
                                                              (" · gw " + s.gw) if s.gw else ""))
                if c["kind"] != "sshuttle":
                    if not s.routes_applied:
                        allgood = bool(s.routes) and s.routes_ok == len(s.routes)
                        add(g, "routes owned by mvm", "info" if allgood else "warn",
                            "routes exist but were added outside mvm (old script / GUI) — down won't remove them" if allgood
                            else "VPN is up but our routes were not applied (started from the GUI?)",
                            "apply routes (key p) so mvm tracks them", fix="apply:" + c["name"])
                    bad = [r for r in s.routes if not r.ok]
                    if s.routes:
                        add(g, "route health", "ok" if not bad else "fail", "%d/%d routes go through %s" % (s.routes_ok, len(s.routes), s.iface),
                            "" if not bad else "e.g. %s %s -> re-apply routes" % (short_route(bad[0].dst), bad[0].note), fix="" if not bad else "apply:" + c["name"])
                    if s.gw and deep:
                        ms = ping(s.gw)
                        add(g, "gateway ping", "ok" if ms is not None else "warn", "%s %s" % (s.gw, "%.0f ms" % ms if ms is not None else "no reply"))
            elif s.state == "activating":
                add(g, "tunnel", "warn", "NetworkManager is still activating it")
            else:
                add(g, "tunnel", "info", "down" + (" — " + s.message if s.message else ""))
        if c.get("probes"):
            if s and s.state in UP_STATES:
                for r in run_probes(list(c["probes"])):
                    add(g, "probe " + r.target, "ok" if r.ok else "fail", "%s%s" % (r.detail, (" · %.0f ms" % r.ms) if r.ms is not None else ""),
                        "" if r.ok else "tunnel is up but this target does not answer: is the IP routed via this VPN (see routes) / is the service running?")
            else:
                add(g, "health probes", "info", "%d configured (run when the VPN is up)" % len(c["probes"]))
        for h in host_entries(c.get("routes", [])):
            ips, err = resolve_host(h, max_age=0 if deep else None)
            add(g, "host " + h, "ok" if ips and not err else ("warn" if ips else "fail"), ", ".join(ips) + (("  " + err) if err else "") if ips else err,
                "" if ips else "name does not resolve — internal names may need the VPN's DNS; use an IP / CIDR instead")
        errs = journal_lines(c, minutes=30, limit=50, errors_only=True)
        if errs:
            add(g, "recent errors (30 min)", "warn", "%d line(s); last: %s" % (len(errs), errs[-1][-110:]), "see Logs tab")
        add(g, "autostart", "info", "enabled" if autostart_enabled(c["name"]) else "off")
    return ck


def apply_fix(fix: str, settings: Dict[str, Any], out: Callable[[str], None]) -> bool:
    kind, _, name = fix.partition(":")
    c = find_config(name) if name else None
    if kind == "never_default" and c:
        rc, o, err = sh([NMCLI, "connection", "modify"] + _nm_ref(c) + ["ipv4.never-default", "yes", "ipv6.never-default", "yes"])
        out("never-default set" if rc == 0 else "failed: " + err.strip())
        return rc == 0
    if kind in ("apply", "reconnect") and c:
        if kind == "reconnect":
            disconnect(c, settings, out)
        return connect(c, settings, out)
    if kind == "down" and c:
        return disconnect(c, settings, out)
    out("this fix needs interaction (%s)" % fix)
    return False


# ======================================================================================
# 11. Rich renderers
# ======================================================================================
def hexrgb(c: str) -> Tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def grad_color(stops: List[str], f: float) -> str:
    f = min(max(f, 0.0), 1.0)
    rgb = [hexrgb(s) for s in stops]
    pos = f * (len(rgb) - 1)
    k = min(int(pos), len(rgb) - 2)
    t = pos - k
    a, b = rgb[k], rgb[k + 1]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(text: str, stops: List[str] = GRAD_MAIN, bold: bool = False):
    from rich.text import Text
    t = Text()
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        t.append(ch, style=("bold " if bold else "") + grad_color(stops, i / n))
    return t


def spark(values: List[float], width: int = 24):
    from rich.text import Text
    chars = "▁▂▃▄▅▆▇█"
    vals = list(values)[-width:]
    if not vals:
        return Text("▁" * 6, style=C_MUTED)
    hi = max(vals) or 1.0
    t = Text()
    for i, v in enumerate(vals):
        t.append(chars[min(int(v / hi * (len(chars) - 1)), len(chars) - 1)], style=grad_color(GRAD_MAIN, i / max(len(vals) - 1, 1)))
    return t


ICON = {"ok": ("✔", C_GREEN), "warn": ("⚠", C_YELLOW), "fail": ("✖", C_RED), "info": ("•", C_BLUE)}
STATE_STYLE = {"up": ("● UP", C_GREEN), "partial": ("◐ PARTIAL", C_YELLOW), "degraded": ("◍ DEGRADED", C_ORANGE), "activating": ("◌ STARTING", C_CYAN),
               "down": ("○ down", C_MUTED), "missing": ("✖ MISSING", C_RED)}


def state_badge(state: str):
    from rich.text import Text
    lab, col = STATE_STYLE.get(state, (state, C_TEXT))
    return Text(lab, style="bold " + col)


def render_doctor(checks: List[Check]):
    from rich import box
    from rich.table import Table
    from rich.text import Text
    t = Table(box=box.ROUNDED, border_style=C_MUTED, header_style="bold " + C_BLUE, expand=True)
    t.add_column("", width=2, no_wrap=True)
    t.add_column("Check", style=C_TEXT, ratio=3)
    t.add_column("Result", ratio=5)
    t.add_column("What to do", style=C_ORANGE, ratio=4)
    group = None
    for c in checks:
        if c.group != group:
            group = c.group
            t.add_row("", Text("▌ " + group.upper(), style="bold " + C_PURPLE), "", "")
        ic, col = ICON[c.status]
        t.add_row(Text(ic, style="bold " + col), c.title, Text(c.detail, style=col if c.status in ("fail", "warn") else C_MUTED),
                  c.hint + ("  [fix: f]" if c.fix else ""))
    return t


def doctor_summary(checks: List[Check]) -> Dict[str, int]:
    s = collections.Counter(c.status for c in checks)
    return {k: s.get(k, 0) for k in ("ok", "warn", "fail", "info")}


def render_summary_line(s: Dict[str, int]):
    from rich.text import Text
    t = Text()
    t.append(" %d OK " % s["ok"], style="bold #1a1b26 on " + C_GREEN)
    t.append(" ")
    t.append(" %d WARN " % s["warn"], style="bold #1a1b26 on " + (C_YELLOW if s["warn"] else C_MUTED))
    t.append(" ")
    t.append(" %d FAIL " % s["fail"], style="bold #1a1b26 on " + (C_RED if s["fail"] else C_MUTED))
    return t


def render_issues(issues: List[Issue]):
    from rich.text import Text
    t = Text()
    if not issues:
        t.append("✔ no problems found", style=C_GREEN)
        return t
    for i in issues:
        ic, col = ("✖", C_RED) if i.level == "error" else ("⚠", C_YELLOW)
        t.append("%s " % ic, style="bold " + col)
        if i.where:
            t.append(i.where + ": ", style=C_PURPLE)
        t.append(i.msg + "\n", style=col)
    return t


def render_vpn_table(statuses: List[VpnStatus]):
    from rich import box
    from rich.table import Table
    from rich.text import Text
    t = Table(box=box.ROUNDED, border_style=C_MUTED, header_style="bold " + C_BLUE, expand=True)
    for col in ("VPN", "Type", "State", "Interface", "Gateway", "Routes", "Up for", "Traffic", "Auto"):
        t.add_column(col)
    for s in statuses:
        r = Text("-", style=C_MUTED)
        if s.routes:
            col = C_GREEN if s.routes_ok == len(s.routes) else (C_YELLOW if s.routes_ok else (C_MUTED if s.state == "down" else C_RED))
            r = Text("%d/%d" % (s.routes_ok, len(s.routes)), style=col)
        elif s.cfg and s.cfg.get("routes"):
            r = Text("%d" % len(expand_routes(s.cfg["routes"])), style=C_MUTED)
        name = Text(s.name, style="bold " + (C_CYAN if s.configured else C_MUTED))
        if not s.configured:
            name.append("  (not managed)", style="italic " + C_MUTED)
        t.add_row(name, KIND_LABEL.get(s.kind, s.kind), state_badge(s.state), s.iface or ("pid %s" % s.pid if s.pid else "-"),
                  s.gw or "-", r, human_dur(now() - s.since) if s.since and s.state in UP_STATES else "-",
                  "↓%s ↑%s" % (human_bytes(s.rx), human_bytes(s.tx)) if s.iface else "-", "✔" if s.autostart else "")
    return t


def render_foreign(fs: List[Foreign], compact: bool = False):
    from rich.text import Text
    t = Text()
    t.append("OTHER VPNs\n", style="bold " + C_PURPLE)
    if not fs:
        t.append("\nnone detected\n", style=C_GREEN)
        return t
    for f in fs:
        col = C_ORANGE if f.owns_default else (C_GREEN if f.state == "connected" else (C_CYAN if f.state in ("running", "present") else C_MUTED))
        t.append("\n◇ %s " % f.name, style="bold " + col)
        t.append(f.state, style=col)
        if f.owns_default:
            t.append("  ⇢ default route", style="bold " + C_ORANGE)
        if f.detail and not compact:
            t.append("\n   " + f.detail[:140], style=C_MUTED)
    return t


def route_owners(statuses: List[VpnStatus]) -> Dict[str, str]:
    """prefix -> which of OUR VPNs carries it right now (sshuttle wins: it intercepts before routing)"""
    own: Dict[str, str] = {}
    for s in statuses:
        for r in s.routes:
            if r.ok and s.kind != "sshuttle":
                own[r.dst] = s.name
    for s in statuses:
        if s.kind == "sshuttle" and s.state in UP_STATES:
            for r in s.routes:
                own[r.dst] = s.name
    return own


def _share_text(dst: str, me: str, claims: Dict[str, List[str]], owners: Dict[str, str]):
    """'● sabalan owns it · ○ Paystar_ovpn waiting' for prefixes claimed by more than one VPN"""
    from rich.text import Text
    names = claims.get(dst, [])
    t = Text()
    if len(names) < 2:
        return t
    owner = owners.get(dst)
    t.append("   ")
    for i, n in enumerate([owner] + [x for x in names if x != owner] if owner in names else names):
        if i:
            t.append(" · ", style=C_MUTED)
        if n == owner:
            t.append("● %s%s" % ("this VPN" if n == me else n, " owns it"), style="bold " + C_GREEN)
        else:
            t.append("○ %s" % ("this VPN" if n == me else n), style=C_YELLOW)
    if not owner:
        t.append("  (no owner up)", style=C_MUTED)
    return t


def render_events(events: List[Dict[str, Any]], with_vpn: bool = False, limit: int = 8):
    from rich.text import Text
    t = Text()
    if not events:
        t.append("no events yet", style=C_MUTED)
        return t
    for e in list(reversed(events))[:limit]:
        ic, col = EVENT_ICON.get(e.get("kind", "info"), EVENT_ICON["info"])
        t.append("%s " % ic, style="bold " + col)
        t.append("%-9s " % human_ago(e.get("ts")), style=C_MUTED)
        if with_vpn:
            t.append("%-14s " % e.get("vpn", "")[:14], style=C_CYAN)
        t.append(str(e.get("msg", ""))[:110] + "\n", style=col if e.get("kind") in ("fail", "dropped", "lost", "probe") else C_TEXT)
    return t


def render_vpn_detail(s: VpnStatus, history: Optional[List[float]] = None, lat: Optional[List[float]] = None,
                      events: Optional[List[Dict[str, Any]]] = None, claims: Optional[Dict[str, List[str]]] = None,
                      owners: Optional[Dict[str, str]] = None, compact: bool = False):
    from rich import box
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    claims, owners = claims or {}, owners or {}
    head = Text()
    head.append(s.name, style="bold " + C_CYAN)
    head.append("   %s   " % KIND_LABEL.get(s.kind, s.kind), style=C_PURPLE)
    head.append_text(state_badge(s.state))
    info = Table.grid(padding=(0, 2))
    info.add_column(style=C_MUTED)
    info.add_column(style=C_TEXT)
    if s.kind == "sshuttle":
        info.add_row("remote", (s.cfg or {}).get("ssh_remote", "-"))
        if s.pid:
            info.add_row("pid", str(s.pid))
    else:
        info.add_row("GUI profile", s.display + ((" (" + s.nm.uuid[:8] + "…)") if s.nm else ""))
        if s.nm and not compact:
            info.add_row("user", s.nm.user or "-")
            remote = s.nm.data.get("remote") or s.nm.data.get("gateway") or "-"
            info.add_row("server", nm_unescape(remote))
    info.add_row("interface", s.iface or "-")
    if not compact:
        info.add_row("local IP", s.local_ip or "-")
    info.add_row("gateway", s.gw or ("(device route)" if s.iface else "-"))
    info.add_row("up for", human_dur(now() - s.since) if s.since and s.state in UP_STATES else "-")
    if s.iface:
        info.add_row("traffic", "↓ %s   ↑ %s" % (human_bytes(s.rx), human_bytes(s.tx)))
    if history:
        info.add_row("rate", spark(history))
    if lat:
        last = lat[-1]
        lt = spark([x if x is not None else 0 for x in lat])
        lt.append("  %s" % ("%.0f ms" % last if last is not None else "no reply"), style=C_TEXT if last is not None else C_RED)
        info.add_row("latency", lt)
    if s.cfg and not compact:
        info.add_row("autostart", "on" if s.autostart else "off")
        if s.cfg.get("note"):
            info.add_row("note", s.cfg["note"])
    if s.message:
        info.add_row("note", Text(s.message, style=C_YELLOW))
    parts: List[Any] = [head, Text(""), info]
    # health probes
    targets = (s.cfg or {}).get("probes") or []
    if targets:
        pt = Table(box=box.SIMPLE_HEAD, header_style="bold " + C_BLUE, expand=True)
        pt.add_column("", width=2)
        pt.add_column("Probe")
        pt.add_column("Result")
        pt.add_column("Latency", justify="right")
        pt.add_column("Checked", style=C_MUTED)
        res = {r.target: r for r in s.probes}
        for t in targets:
            r = res.get(t)
            if not r:
                pt.add_row(Text("·", style=C_MUTED), t, Text("not checked" if s.state in UP_STATES else "VPN down", style=C_MUTED), "", "")
            else:
                pt.add_row(Text("✔" if r.ok else "✖", style=C_GREEN if r.ok else C_RED), t, Text(r.detail, style=C_TEXT if r.ok else C_RED),
                           "%.0f ms" % r.ms if r.ms is not None else "-", human_ago(r.ts))
        parts += [Text("\nhealth probes", style="bold " + C_PURPLE), pt]
    if s.nm and s.nm.secret_flags and not compact:
        sec = Text("\ncredentials (from the GUI profile)\n", style="bold " + C_PURPLE)
        for k, f in sorted(s.nm.secret_flags.items()):
            col = C_GREEN if f == 0 else (C_YELLOW if f == 2 else C_CYAN)
            sec.append("  %-26s %s\n" % (SECRET_LABEL.get(k, k), FLAG_TEXT.get(f, str(f))), style=col)
        parts.append(sec)
    if not compact and (s.routes or (s.cfg and s.cfg.get("routes"))):
        rt = Table(box=box.SIMPLE_HEAD, header_style="bold " + C_BLUE, expand=True)
        rt.add_column("", width=2)
        rt.add_column("Destination")
        rt.add_column("Kernel sends it via")
        rt.add_column("Note", style=C_MUTED)
        srcs = route_sources(s.cfg.get("routes", []) if s.cfg else [])
        rows = s.routes or [RouteHealth(r, "", "", False, "", srcs.get(r, "")) for r in expand_routes(s.cfg.get("routes", []))]
        for r in rows:
            if r.ok:
                ic = Text("✔", style=C_GREEN)
            elif r.owner:
                ic = Text("○", style=C_YELLOW)
            elif s.state == "down":
                ic = Text("·", style=C_MUTED)
            else:
                ic = Text("✖", style=C_RED)
            share = _share_text(r.dst, s.name, claims, owners)
            note = Text("" if (r.owner and share.plain.strip()) else r.note, style=C_YELLOW if r.owner else C_MUTED)
            if r.src:
                note.append(("  " if r.note else "") + ("⟵ " + ("host " if is_host(r.src) else "range ") + entry_label(r.src)), style=C_MUTED)
            note.append_text(share)
            rt.add_row(ic, short_route(r.dst), "%s%s" % (r.dev or "-", (" → " + r.via) if r.via else ""), note)
        for h in host_entries((s.cfg or {}).get("routes", [])):
            if not cached_host(h):
                rt.add_row(Text("?", style=C_YELLOW), h, "-", Text("not resolved yet (resolves when the VPN comes up)", style=C_YELLOW))
        parts += [Text("\nroutes", style="bold " + C_PURPLE), rt]
    if events is not None:
        parts += [Text("\nevents", style="bold " + C_PURPLE), render_events(events, limit=4 if compact else 8)]
    col = {"up": C_BLUE, "degraded": C_ORANGE, "partial": C_YELLOW}.get(s.state, C_MUTED)
    return Panel(Group(*parts), border_style=col, box=box.ROUNDED)


def render_graph(statuses: List[VpnStatus], fs: List[Foreign]):
    """VPN -> routes -> where the kernel sends each one right now (● owner / ○ waiting for shared prefixes)"""
    from rich.text import Text
    from rich.tree import Tree
    root = Tree(gradient("◆ routing map", bold=True), guide_style=C_MUTED)
    claims: Dict[str, List[str]] = collections.defaultdict(list)
    for s in statuses:
        for r in expand_routes((s.cfg or {}).get("routes", [])):
            claims[r].append(s.name)
    owners = route_owners(statuses)
    for s in statuses:
        if not s.configured and s.state == "down":
            continue
        lab = Text()
        lab.append_text(state_badge(s.state))
        lab.append("  %s" % s.name, style="bold " + C_CYAN)
        lab.append("  [%s]" % KIND_LABEL.get(s.kind, s.kind), style=C_PURPLE)
        if s.iface:
            lab.append("  %s" % s.iface, style=C_TEXT)
            lab.append(" → %s" % (s.gw or "device"), style=C_MUTED)
        if s.kind == "sshuttle" and (s.cfg or {}).get("ssh_remote"):
            lab.append("  ssh %s" % s.cfg["ssh_remote"], style=C_TEXT)
        if s.probes:
            okp = sum(1 for p in s.probes if p.ok)
            lab.append("  ◍ probes %d/%d" % (okp, len(s.probes)), style=C_GREEN if okp == len(s.probes) else C_ORANGE)
        node = root.add(lab)
        srcs = route_sources((s.cfg or {}).get("routes", []))
        rows = s.routes or [RouteHealth(r, "", "", False, "", srcs.get(r, "")) for r in expand_routes((s.cfg or {}).get("routes", []))]
        if not rows and not s.configured:
            node.add(Text("not managed: adopt it to give it routes", style="italic " + C_MUTED))
        group_nodes: Dict[str, Any] = {}
        for r in rows[:400]:
            parent = node
            if r.src:   # prefixes of a range / hostname hang under one node
                if r.src not in group_nodes:
                    members = [x for x in rows if x.src == r.src]
                    okc = sum(1 for x in members if x.ok)
                    col = C_MUTED if s.state == "down" else (C_GREEN if okc == len(members) else C_RED if not okc else C_YELLOW)
                    kind = "⌂ host" if is_host(r.src) else "⇔ range"
                    group_nodes[r.src] = node.add(Text("%s %s  → %d prefix(es)%s" % (kind, entry_label(r.src), len(members),
                                                       "" if s.state == "down" else "  %d/%d ok" % (okc, len(members))), style="bold " + col))
                parent = group_nodes[r.src]
            t = Text()
            if s.state == "down":
                t.append("· %s" % short_route(r.dst), style=C_MUTED)
                if r.dev:
                    t.append("   now via %s" % r.dev, style=C_MUTED)
            elif r.ok:
                t.append("✔ %s" % short_route(r.dst), style=C_GREEN)
            elif r.owner:
                t.append("○ %s" % short_route(r.dst), style=C_YELLOW)
            else:
                t.append("✖ %s" % short_route(r.dst), style=C_RED)
                t.append("   %s" % (r.note or "not routed"), style=C_ORANGE)
            t.append_text(_share_text(r.dst, s.name, claims, owners))
            parent.add(t)
        for h in host_entries((s.cfg or {}).get("routes", [])):
            if not cached_host(h):
                node.add(Text("⌂ host %s  (not resolved yet)" % h, style=C_YELLOW))
    for f in fs:
        lab = Text("◇ %s  %s" % (f.name, f.state), style=C_ORANGE if f.owns_default else (C_GREEN if f.state == "connected" else C_MUTED))
        if f.ifaces:
            lab.append("  " + ",".join(f.ifaces), style=C_TEXT)
        root.add(lab)
    for d in default_routes():
        root.add(Text("⇢ default → %s%s%s" % (d.dev, (" via " + d.via) if d.via else "", "" if d.table in ("main", "") else " (table %s)" % d.table),
                      style=C_BLUE))
    if any(len(v) > 1 for v in claims.values()):
        root.add(Text("● = carries the shared IP now · ○ = also claims it, waiting · press p on a VPN to take its shared IPs", style="italic " + C_MUTED))
    return root


def render_banner(statuses: List[VpnStatus], fs: List[Foreign]):
    from rich.text import Text
    t = Text()
    t.append_text(gradient("⚙ multi-vpn-manager", bold=True))
    up = sum(1 for s in statuses if s.state in UP_STATES)
    t.append("   %d up" % up, style="bold " + (C_GREEN if up else C_MUTED))
    t.append(" / %d managed" % sum(1 for s in statuses if s.configured), style=C_MUTED)
    fc = [f for f in fs if f.state == "connected"]
    if fc:
        t.append("   other: " + ", ".join(f.name for f in fc[:3]), style=C_ORANGE)
    t.append("   " + dt.datetime.now().strftime("%H:%M:%S"), style=C_MUTED)
    return t


# ======================================================================================
# 12. CLI
# ======================================================================================
def _console():
    from rich.console import Console
    mode = os.environ.get("TEXTUAL_COLOR_SYSTEM", "auto")
    return Console(color_system=mode if mode in ("truecolor", "256", "standard") else "auto")


def cli_colors(args) -> int:
    """show which colour mode is used and a gradient test strip"""
    mode = os.environ.get("TEXTUAL_COLOR_SYSTEM", "auto")
    if not can_import("rich"):
        print("colour mode: %s (rich not installed: python3 mvm.py bootstrap)" % mode)
        return 0
    from rich.text import Text
    con = _console()
    con.print("colour mode: [bold]%s[/]  (TERM=%s, COLORTERM=%s)  rich uses: %s" % (mode, os.environ.get("TERM", ""), os.environ.get("COLORTERM", ""), con.color_system))
    strip = Text()
    for i in range(72):
        strip.append("█", style=grad_color([C_RED, C_YELLOW, C_GREEN, C_CYAN, C_BLUE, C_PURPLE, C_PINK], i / 71))
    con.print(strip)
    con.print(gradient("smooth gradient = true colour works · banded = 256 colours", bold=True))
    bg = Text("  dark navy panel background  ", style="%s on %s" % (C_TEXT, C_PANEL))
    con.print(bg)
    con.print("If the strip is banded or the panel looks peach/pink: use  --colors truecolor  (or 256 if your terminal has no 24-bit support)")
    return 0


def _plain_doctor(checks: List[Check]) -> None:
    group = None
    for c in checks:
        if c.group != group:
            group = c.group
            print("\n== %s" % group.upper())
        print("  [%-4s] %-34s %s%s" % (c.status.upper(), c.title, c.detail, ("\n         -> " + c.hint) if c.hint else ""))


def _need(key: str) -> Dict[str, Any]:
    c = find_config(key)
    if not c:
        print("no managed VPN named %r. Known: %s" % (key, ", ".join(x["name"] for x in load_configs()) or "-"))
        print("adopt a GUI VPN first:  mvm adopt <profile name>   (see: mvm list)")
        sys.exit(2)
    return c


def cli_list(args) -> int:
    sts = collect_status(with_routes=False)
    if can_import("rich"):
        _console().print(render_vpn_table(sts))
    else:
        for s in sts:
            print("%-22s %-11s %-10s %-8s %s" % (s.name, KIND_LABEL.get(s.kind, s.kind), s.state, s.iface or "-", "" if s.configured else "(not managed)"))
    return 0


def cli_status(args) -> int:
    while True:
        probe_round(collect_status(False))
        sts = collect_status(True)
        fs = detect_foreign(own_ifaces(sts), deep=True)
        if args.json:
            print(json.dumps([{"name": s.name, "kind": s.kind, "state": s.state, "iface": s.iface, "gw": s.gw, "since": s.since,
                               "routes_ok": s.routes_ok, "routes": len(s.routes), "managed": s.configured} for s in sts]
                             + [{"foreign": f.name, "state": f.state, "detail": f.detail} for f in fs], indent=2))
            return 0
        if not can_import("rich"):
            cli_list(args)
            return 0
        con = _console()
        if args.watch:
            con.clear()
        con.print(render_banner(sts, fs))
        con.print(render_vpn_table(sts))
        for s in sts:
            if s.state in UP_STATES or (args.name and args.name in (s.name, s.display)):
                con.print(render_vpn_detail(s))
        con.print(render_foreign(fs))
        if not args.watch:
            return 0
        time.sleep(3)


def cli_up(args) -> int:
    c = _need(args.name)
    ok = connect_with_retries(c, load_settings(), args.retries, print)
    if not sys.stdout.isatty():   # autostart (systemd) or a script: tell the desktop
        desktop_notify("%s %s" % (c["name"], "connected" if ok else "failed to connect"),
                       "autostart: %s" % ("routes applied" if ok else "see: mvm logs %s" % c["name"]), "normal" if ok else "critical", c["name"])
    return 0 if ok else 1


def cli_down(args) -> int:
    return 0 if disconnect(_need(args.name), load_settings(), print) else 1


def cli_restart(args) -> int:
    c = _need(args.name)
    s = load_settings()
    disconnect(c, s, print)
    return 0 if connect(c, s, print) else 1


def cli_apply(args) -> int:
    c = _need(args.name)
    if c["kind"] == "sshuttle":
        print("sshuttle routes are fixed at start: use restart")
        return 1
    return 0 if connect(c, load_settings(), print) else 1


def cli_routes(args) -> int:
    c = _need(args.name)
    act = args.action or "list"
    if act == "list":
        for r in c.get("routes", []):
            exp = expand_entry(r)
            n_ = norm_entry(r) or ""
            print(entry_label(r) + (("   = " + " ".join(short_route(x) for x in exp)) if is_range(n_) or is_host(n_) else ""))
        print("-- %d entries, %d kernel routes" % (len(c.get("routes", [])), len(expand_routes(c.get("routes", [])))))
        return 0
    if act == "add":
        good, bad = parse_routes_text("\n".join(args.items))
        c["routes"] = list(dict.fromkeys(list(c.get("routes", [])) + good))
    elif act == "rm":
        rm = {norm_entry(x) for x in parse_routes_text("\n".join(args.items))[0]} | {norm_entry(x) for x in args.items}
        c["routes"] = [r for r in c.get("routes", []) if r not in rm]
        bad = []
    elif act == "import":
        good, bad = [], []
        for f in args.items:
            g2, b2 = parse_routes_text(Path(f).expanduser().read_text())
            good += g2
            bad += b2
        c["routes"] = list(dict.fromkeys(list(c.get("routes", [])) + good))
    elif act == "clear":
        c["routes"], bad = [], []
    else:
        print("unknown action")
        return 2
    for b in bad:
        print("skipped invalid: %s" % b)
    save_config(c)
    print("%s: %d route(s) saved. Apply to a running VPN with: mvm apply %s" % (c["name"], len(c["routes"]), c["name"]))
    return 0


def adopt_profile(p: NMProfile, name: Optional[str] = None, routes: Optional[List[str]] = None) -> Dict[str, Any]:
    c = default_config(slug(name or p.name), p.kind)
    c.update({"nm_uuid": p.uuid, "nm_name": p.name, "routes": routes or []})
    save_config(c)
    return c


def cli_adopt(args) -> int:
    profs = nm_profiles()
    p = next((x for x in profs if args.profile in (x.name, x.uuid)), None) or next((x for x in profs if x.name.lower() == args.profile.lower()), None)
    if not p:
        print("no NetworkManager VPN called %r. Available: %s" % (args.profile, ", ".join(x.name for x in profs) or "-"))
        return 2
    routes: List[str] = []
    for f in args.routes_file or []:
        g, bad = parse_routes_text(Path(f).expanduser().read_text())
        routes += g
        for b in bad:
            print("skipped invalid: %s" % b)
    c = adopt_profile(p, args.name, list(dict.fromkeys(routes)))
    if args.gateway:
        c["gateway"] = args.gateway
        save_config(c)
    print("adopted %s as '%s' (%s, %d routes) -> %s" % (p.name, c["name"], KIND_LABEL.get(p.kind, p.kind), len(c["routes"]), config_path(c["name"])))
    return 0


def cli_new_sshuttle(args) -> int:
    c = default_config(slug(args.name), "sshuttle")
    c["ssh_remote"] = args.remote
    c["ssh_args"] = args.ssh_args or ""
    for f in args.routes_file or []:
        g, _ = parse_routes_text(Path(f).expanduser().read_text())
        c["routes"] += g
    c["routes"] = list(dict.fromkeys(c["routes"]))
    for i in validate_config(c):
        print("%s: %s" % (i.level, i.msg))
    save_config(c)
    print("created sshuttle profile '%s' (%d routes)" % (c["name"], len(c["routes"])))
    return 0


def cli_delete(args) -> int:
    c = _need(args.name)
    if load_state(c["name"]):
        disconnect(c, load_settings(), print)
    delete_config(c["name"])
    print("config renamed to %s.json.deleted (the GUI profile is untouched)" % c["name"])
    return 0


def cli_secrets(args) -> int:
    c = _need(args.name)
    p = next((x for x in nm_profiles() if x.uuid == c.get("nm_uuid") or x.name == c.get("nm_name")), None)
    if not p:
        print("GUI profile not found")
        return 1
    keys = sorted(p.secret_flags) or ["password"]
    stored, _ = nm_secret_keys_stored(p.uuid)
    print("Storing secrets of '%s' in the system profile (flags=0). Leave empty to keep the current value." % p.name)
    vals = {}
    for k in keys:
        cur = " [stored]" if stored and k in stored else ""
        v = getpass.getpass("%s%s: " % (SECRET_LABEL.get(k, k), cur))
        if v:
            vals[k] = v
    if not vals:
        print("nothing changed")
        return 0
    ok, msg = nm_set_secrets(p.uuid, vals, use_sudo="auto")
    if not ok:
        print("plain nmcli failed (%s) -> retrying with sudo" % msg)
        ok, msg = nm_set_secrets(p.uuid, vals, use_sudo="interactive")
    vlog(c["name"], "secrets updated: %s (%s)" % (", ".join(sorted(vals)), "ok" if ok else "failed"))
    print(("✔ " if ok else "✖ ") + msg)
    return 0 if ok else 1


def cli_doctor(args) -> int:
    checks = run_doctor(load_settings(), args.name, deep=args.deep)
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    elif can_import("rich"):
        con = _console()
        con.print(render_doctor(checks))
        con.print(render_summary_line(doctor_summary(checks)))
    else:
        _plain_doctor(checks)
    if args.fix:
        s = load_settings()
        for c in checks:
            if not c.fix:
                continue
            print("\n>> fix: %s (%s)" % (c.title, c.fix))
            if c.fix == "sudoers":
                print(install_sudoers(True)[1])
            elif c.fix.startswith("secrets:"):
                cli_secrets(argparse.Namespace(name=c.fix.split(":", 1)[1]))
            else:
                apply_fix(c.fix, s, print)
    return 1 if any(c.status == "fail" for c in checks) else 0


def cli_logs(args) -> int:
    c = _need(args.name)
    for l in tail_file(log_path(c["name"]), args.n):
        print(l)
    if args.journal:
        print("---- journal (NetworkManager / plugins) ----")
        for l in journal_lines(c, minutes=load_settings().get("journal_minutes", 180), limit=args.n):
            print(l)
    if args.follow:
        p = log_path(c["name"])
        pos = p.stat().st_size if p.exists() else 0
        try:
            while True:
                time.sleep(1)
                if p.exists() and p.stat().st_size > pos:
                    with p.open() as f:
                        f.seek(pos)
                        sys.stdout.write(f.read())
                        pos = f.tell()
                    sys.stdout.flush()
        except KeyboardInterrupt:
            pass
    return 0


def cli_graph(args) -> int:
    sts = collect_status(True)
    fs = detect_foreign(own_ifaces(sts))
    _console().print(render_graph(sts, fs))
    return 0


def cli_foreign(args) -> int:
    sts = collect_status(False)
    fs = detect_foreign(own_ifaces(sts))
    if can_import("rich"):
        _console().print(render_foreign(fs))
    else:
        for f in fs:
            print("%-20s %-12s %s" % (f.name, f.state, f.detail))
    return 0


def cli_autostart(args) -> int:
    c = _need(args.name)
    ok, msg = set_autostart(c["name"], args.state == "on")
    print(("✔ " if ok else "✖ ") + msg)
    return 0 if ok else 1


def cli_sudoers(args) -> int:
    if args.action == "show":
        print(sudoers_text())
        return 0
    if args.action == "check":
        print("ip:", sudoers_ok())
        print("sshuttle:", sshuttle_sudo_ok())
        return 0
    print("This installs %s with:\n" % SUDOERS_FILE)
    print(sudoers_text())
    ok, msg = install_sudoers(True)
    print(("✔ " if ok else "✖ ") + msg)
    return 0 if ok else 1


def cli_probes(args) -> int:
    c = _need(args.name)
    act = args.action or "list"
    if act in ("add", "rm"):
        cur = list(c.get("probes") or [])
        for t in args.items:
            if act == "add":
                if not parse_probe(t):
                    print("invalid probe %r (host:port · http(s)://url · ping:host)" % t)
                    return 2
                if t not in cur:
                    cur.append(t)
            elif t in cur:
                cur.remove(t)
        c["probes"] = cur
        save_config(c)
        print("%s: %d probe(s)" % (c["name"], len(cur)))
        return 0
    if act == "run":
        res = run_probes(list(c.get("probes") or []))
        save_probe_results(c["name"], res)
        for r in res:
            print("%s %-40s %-24s %s" % ("✔" if r.ok else "✖", r.target, r.detail, ("%.0f ms" % r.ms) if r.ms is not None else ""))
        return 0 if all(r.ok for r in res) else 1
    for t in c.get("probes") or []:
        print(t)
    return 0


def cli_export(args) -> int:
    data = export_bundle(args.names or None, args.strip_routes, args.strip_hosts)
    out = Path(args.output).expanduser() if args.output else Path("mvm-export-%s.json" % dt.date.today().isoformat())
    atomic_write(out, json.dumps(data, indent=2) + "\n")
    print("exported %d VPN config(s) to %s (no secrets%s)" % (len(data["vpns"]), out,
          ", routes stripped" if args.strip_routes else "") + (", hosts stripped" if args.strip_hosts else ""))
    return 0


def cli_import(args) -> int:
    try:
        data = json.loads(Path(args.file).expanduser().read_text())
        res = import_bundle(data, args.overwrite)
    except (OSError, ValueError) as e:
        print("✖ %s" % e)
        return 1
    for name, what in res:
        print("%s %-20s %s" % ("✔" if not what.startswith("skipped") else "·", name, what))
    return 0


def cli_dns(args) -> int:
    cs = [_need(args.name)] if args.name else load_configs()
    for c in cs:
        for h in host_entries(c.get("routes", [])):
            ips, err = resolve_host(h, max_age=0)
            print("%-16s %-36s %s%s" % (c["name"], h, ", ".join(ips) or "-", ("  (" + err + ")") if err else ""))
        ch = dns_changed(c)
        if ch:
            print("  %s: IPs changed since the routes were applied (+%d −%d) — run: mvm apply %s" % (c["name"], len(ch[1] - ch[0]), len(ch[0] - ch[1]), c["name"]))
    return 0


def cli_bootstrap(args) -> int:
    return 0 if bootstrap() else 1


# ======================================================================================
# 13. Textual app
# ======================================================================================
def make_app():
    """build the Textual app (separate from run_tui so tests can drive it headlessly)"""
    from textual import on, work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.screen import ModalScreen
    from textual.widgets import Button, DataTable, Footer, Input, Label, RichLog, Select, Static, Switch, TabbedContent, TabPane, TextArea
    from rich.text import Text
    from rich.console import Group
    from rich.panel import Panel
    from rich import box

    # ---------------------------------------------------------------- modals
    class Confirm(ModalScreen[bool]):
        def __init__(self, title: str, body: Any, danger: bool = False, yes: str = "Yes") -> None:
            super().__init__()
            self.t, self.b, self.danger, self.yes = title, body, danger, yes

        def compose(self) -> ComposeResult:
            with Vertical(classes="modal"):
                yield Static(gradient(self.t, GRAD_WARM if self.danger else GRAD_MAIN, bold=True))
                yield Static(self.b, classes="modal-body")
                with Horizontal(classes="buttons"):
                    yield Button(self.yes, variant="error" if self.danger else "success", id="yes")
                    yield Button("Cancel", id="no")

        @on(Button.Pressed, "#yes")
        def _y(self) -> None:
            self.dismiss(True)

        @on(Button.Pressed, "#no")
        def _n(self) -> None:
            self.dismiss(False)

        def key_escape(self) -> None:
            self.dismiss(False)

    class RunLog(ModalScreen[None]):
        """live output of an up / down / fix operation"""
        def __init__(self, title: str, job: Callable[[Callable[[str], None]], bool]) -> None:
            super().__init__()
            self.t, self.job = title, job
            self.finished = False

        def compose(self) -> ComposeResult:
            with Vertical(classes="modal huge"):
                yield Static(gradient(self.t, bold=True))
                yield RichLog(id="log", markup=False, wrap=True, highlight=False)
                yield Static("", id="status")
                with Horizontal(classes="buttons"):
                    yield Button("Close", id="close", variant="primary")

        def on_mount(self) -> None:
            self.query_one("#status", Static).update(Text("working …", style="italic " + C_YELLOW))
            self.go()

        def put(self, line: str) -> None:
            st = C_TEXT
            if line.startswith("✖"):
                st = C_RED
            elif line.startswith("⚠"):
                st = C_YELLOW
            elif line.startswith("✔"):
                st = C_GREEN
            elif "===" in line:
                st = "bold " + C_PURPLE
            elif "nmcli:" in line or "journal:" in line:
                st = C_CYAN
            self.query_one("#log", RichLog).write(Text(line, style=st))

        @work(thread=True)
        def go(self) -> None:
            def say(l: str) -> None:
                self.app.call_from_thread(self.put, l)
            try:
                ok = bool(self.job(say))
            except Exception as e:  # noqa: BLE001
                say("✖ internal error: %r" % e)
                ok = False
            self.app.call_from_thread(self.done, ok)

        def done(self, ok: bool) -> None:
            self.finished = True
            self.query_one("#status", Static).update(Text("✔ done" if ok else "✖ failed — see the lines above / Logs tab / Troubleshoot",
                                                          style="bold " + (C_GREEN if ok else C_RED)))

        @on(Button.Pressed, "#close")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    class ConfigForm(ModalScreen[Optional[Dict[str, Any]]]):
        def __init__(self, cfg: Dict[str, Any], others: List[Dict[str, Any]], is_new: bool = False) -> None:
            super().__init__()
            self.cfg, self.others, self.is_new = dict(cfg), others, is_new

        def compose(self) -> ComposeResult:
            c = self.cfg
            ssh = c["kind"] == "sshuttle"
            with Vertical(classes="modal wide"):
                yield Static(gradient(("New sshuttle profile" if ssh else "Adopt %s" % c.get("nm_name")) if self.is_new else "Edit %s" % c["name"], bold=True))
                yield Static(Text("%s%s" % (KIND_LABEL.get(c["kind"], c["kind"]), ("  ·  GUI profile: %s" % c.get("nm_name")) if not ssh else ""), style=C_PURPLE))
                yield Label("Name (used for logs, state and autostart)")
                yield Input(value=c["name"], id="name", disabled=not self.is_new)
                if ssh:
                    yield Label("SSH remote  (user@host[:port] or ~/.ssh/config alias)")
                    yield Input(value=c.get("ssh_remote", ""), id="remote", placeholder="user@203.0.113.10:22")
                    yield Label("Extra sshuttle arguments  (e.g. --dns  -x 10.0.0.5  -e 'ssh -i ~/.ssh/key')")
                    yield Input(value=c.get("ssh_args", ""), id="sargs")
                else:
                    yield Label("Gateway  ('auto' = PPP peer / pushed gateway, else a device route on the tunnel)")
                    yield Input(value=c.get("gateway", "auto"), id="gw")
                yield Label("Routes through this VPN  (one IP, CIDR or range per line, # comments ok — only these go through the tunnel)")
                yield TextArea("\n".join(short_route(r) for r in c.get("routes", [])), id="routes")
                yield Static(Text("formats: 1.2.3.4   10.0.0.0/24   10.0.0.5-10.0.0.20   10.0.0.5-20   10.1.2.*   git.example.com", style=C_MUTED))
                yield Label("Health probes  (space/comma separated: host:port · http(s)://url · ping:host — checked while the VPN is up)")
                yield Input(value=" ".join(c.get("probes") or []), id="probes", placeholder="192.0.2.22:9000  https://intranet.example/health")
                with Horizontal(classes="row"):
                    if not ssh:
                        yield Label("never default route", classes="inline")
                        yield Switch(value=bool(c.get("never_default", True)), id="nd")
                    yield Label("notify", classes="inline")
                    yield Switch(value=bool(c.get("notify", True)), id="notify")
                    yield Label("note", classes="inline")
                    yield Input(value=c.get("note", ""), id="note")
                yield Static("", id="issues")
                with Horizontal(classes="buttons"):
                    yield Button("Save", variant="success", id="save")
                    yield Button("Import file…", id="imp")
                    yield Button("Cancel", id="cancel")

        def on_mount(self) -> None:
            self.check()

        def value(self) -> Dict[str, Any]:
            c = dict(self.cfg)
            c["name"] = slug(self.query_one("#name", Input).value) if self.is_new else c["name"]
            good, bad = parse_routes_text(self.query_one("#routes", TextArea).text)
            c["routes"] = good
            c["_bad"] = bad
            c["note"] = self.query_one("#note", Input).value.strip()
            c["probes"] = [t for t in re.split(r"[\s,]+", self.query_one("#probes", Input).value.strip()) if t]
            c["notify"] = self.query_one("#notify", Switch).value
            if c["kind"] == "sshuttle":
                c["ssh_remote"] = self.query_one("#remote", Input).value.strip()
                c["ssh_args"] = self.query_one("#sargs", Input).value.strip()
            else:
                c["gateway"] = self.query_one("#gw", Input).value.strip() or "auto"
                c["never_default"] = self.query_one("#nd", Switch).value
            return c

        def check(self) -> None:
            v = self.value()
            iss = validate_config(v, self.others)
            iss += [Issue("error", "not an IP / CIDR / range / hostname: %s" % b, "routes") for b in v["_bad"][:5]]
            if self.is_new and any(o["name"] == v["name"] for o in self.others):
                iss.append(Issue("error", "a VPN with this name already exists", "name"))
            nr = sum(1 for r in v["routes"] if is_range(r))
            nh = sum(1 for r in v["routes"] if is_host(r))
            extra = ", ".join(x for x in (("%d range%s" % (nr, "" if nr == 1 else "s")) if nr else "", ("%d hostname%s" % (nh, "" if nh == 1 else "s")) if nh else "") if x)
            t = Text("%d entr%s%s → %d kernel route(s)%s\n" % (len(v["routes"]), "y" if len(v["routes"]) == 1 else "ies", (" (%s)" % extra) if extra else "",
                                                           len(expand_routes(v["routes"])), " + hostnames resolved at apply time" if nh else ""), style=C_CYAN)
            t.append_text(render_issues(iss))
            self.query_one("#issues", Static).update(t)
            self.query_one("#save", Button).disabled = any(i.level == "error" for i in iss)

        @on(Input.Changed)
        @on(TextArea.Changed)
        @on(Switch.Changed)
        def _chg(self) -> None:
            if self.is_mounted:
                self.check()

        @on(Button.Pressed, "#imp")
        def _imp(self) -> None:
            def done(path: Optional[str]) -> None:
                if not path:
                    return
                try:
                    txt = Path(path).expanduser().read_text()
                except OSError as e:
                    self.app.notify(str(e), severity="error")
                    return
                ta = self.query_one("#routes", TextArea)
                ta.load_text((ta.text.rstrip() + "\n" if ta.text.strip() else "") + txt)
            self.app.push_screen(TextPrompt("Import routes", "Path of a text file with one IP/CIDR per line", "~/.vpn-routes.txt"), done)

        @on(Button.Pressed, "#save")
        def _save(self) -> None:
            v = self.value()
            v.pop("_bad", None)
            self.dismiss(v)

        @on(Button.Pressed, "#cancel")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    class TextPrompt(ModalScreen[Optional[str]]):
        def __init__(self, title: str, label: str, value: str = "") -> None:
            super().__init__()
            self.t, self.l, self.v = title, label, value

        def compose(self) -> ComposeResult:
            with Vertical(classes="modal"):
                yield Static(gradient(self.t, bold=True))
                yield Label(self.l)
                yield Input(value=self.v, id="val")
                with Horizontal(classes="buttons"):
                    yield Button("OK", variant="success", id="ok")
                    yield Button("Cancel", id="cancel")

        @on(Button.Pressed, "#ok")
        @on(Input.Submitted, "#val")
        def _ok(self) -> None:
            self.dismiss(self.query_one("#val", Input).value.strip() or None)

        @on(Button.Pressed, "#cancel")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    class SecretsForm(ModalScreen[Optional[Dict[str, str]]]):
        def __init__(self, prof: NMProfile, stored: Optional[set]) -> None:
            super().__init__()
            self.p, self.stored = prof, stored

        def compose(self) -> ComposeResult:
            keys = sorted(self.p.secret_flags) or ["password"]
            with Vertical(classes="modal"):
                yield Static(gradient("Credentials of %s" % self.p.name, bold=True))
                yield Static(Text("Stored in the GUI profile itself (flags=0): no prompts at boot, the GUI uses them too.\n"
                                  "All secrets are written in ONE call (writing them one by one erases the others).\n"
                                  "Leave a field empty to keep the current value. Values are never logged.", style=C_MUTED), classes="modal-body")
                for k in keys:
                    cur = FLAG_TEXT.get(self.p.secret_flags.get(k, 0), "?")
                    have = " · stored" if self.stored and k in self.stored else (" · NOT stored" if self.stored is not None else "")
                    yield Label("%s   (%s%s)" % (SECRET_LABEL.get(k, k), cur, have))
                    yield Input(password=True, id="sec-" + re.sub(r"[^A-Za-z0-9_-]", "_", k), name=k)
                with Horizontal(classes="buttons"):
                    yield Button("Save", variant="success", id="ok")
                    yield Button("Cancel", id="cancel")

        @on(Button.Pressed, "#ok")
        def _ok(self) -> None:
            vals = {w.name: w.value for w in self.query(Input) if w.value and w.name}
            self.dismiss(vals or None)

        @on(Button.Pressed, "#cancel")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    class ExportForm(ModalScreen[Optional[Dict[str, Any]]]):
        def __init__(self, names: List[str]) -> None:
            super().__init__()
            self.names = names

        def compose(self) -> ComposeResult:
            from textual.widgets import SelectionList
            with Vertical(classes="modal"):
                yield Static(gradient("Export VPN configs", bold=True))
                yield Static(Text("A JSON bundle of the configs below. Secrets are never included (they stay in NetworkManager);\n"
                                  "machine-specific bits (profile UUIDs, autostart) are dropped.", style=C_MUTED), classes="modal-body")
                yield SelectionList(*[(n, n, True) for n in self.names], id="sel")
                yield Label("Save to")
                yield Input(value=str(Path.home() / ("mvm-export-%s.json" % dt.date.today().isoformat())), id="path")
                with Horizontal(classes="row"):
                    yield Label("strip routes + probes", classes="inline")
                    yield Switch(value=False, id="sr")
                    yield Label("strip ssh hosts / hostnames", classes="inline")
                    yield Switch(value=False, id="sh")
                with Horizontal(classes="buttons"):
                    yield Button("Export", variant="success", id="ok")
                    yield Button("Cancel", id="cancel")

        @on(Button.Pressed, "#ok")
        def _ok(self) -> None:
            from textual.widgets import SelectionList
            sel = list(self.query_one("#sel", SelectionList).selected)
            if not sel:
                self.app.notify("select at least one VPN", severity="warning")
                return
            self.dismiss({"names": sel, "path": self.query_one("#path", Input).value.strip(),
                          "strip_routes": self.query_one("#sr", Switch).value, "strip_hosts": self.query_one("#sh", Switch).value})

        @on(Button.Pressed, "#cancel")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    class ImportForm(ModalScreen[Optional[Dict[str, Any]]]):
        def compose(self) -> ComposeResult:
            with Vertical(classes="modal"):
                yield Static(gradient("Import VPN configs", bold=True))
                yield Label("Bundle file (made by Export / `mvm export`)")
                yield Input(value=str(Path.home() / ("mvm-export-%s.json" % dt.date.today().isoformat())), id="path")
                with Horizontal(classes="row"):
                    yield Label("overwrite configs with the same name", classes="inline")
                    yield Switch(value=False, id="ow")
                yield Static("", id="preview", classes="modal-body")
                with Horizontal(classes="buttons"):
                    yield Button("Import", variant="success", id="ok")
                    yield Button("Cancel", id="cancel")

        def on_mount(self) -> None:
            self.preview()

        @on(Input.Changed, "#path")
        def preview(self) -> None:
            pv = self.query_one("#preview", Static)
            try:
                d = json.loads(Path(self.query_one("#path", Input).value.strip()).expanduser().read_text())
                if d.get("format") != EXPORT_FORMAT:
                    raise ValueError("not a multi-vpn-manager export")
                have = {c["name"] for c in load_configs()}
                t = Text("%d VPN(s), exported %s\n" % (len(d.get("vpns", [])), d.get("exported", "?")), style=C_CYAN)
                for e in d.get("vpns", [])[:12]:
                    n = slug(str(e.get("name", "?")))
                    t.append("  %s %-20s %s%s\n" % ("●" if n in have else "+", n, KIND_LABEL.get(e.get("kind"), e.get("kind")),
                                                    "  (exists)" if n in have else ""), style=C_YELLOW if n in have else C_TEXT)
                pv.update(t)
                self.query_one("#ok", Button).disabled = False
            except (OSError, ValueError, AttributeError) as e:
                pv.update(Text(str(e), style=C_RED))
                self.query_one("#ok", Button).disabled = True

        @on(Button.Pressed, "#ok")
        def _ok(self) -> None:
            self.dismiss({"path": self.query_one("#path", Input).value.strip(), "overwrite": self.query_one("#ow", Switch).value})

        @on(Button.Pressed, "#cancel")
        def _c(self) -> None:
            self.dismiss(None)

        def key_escape(self) -> None:
            self.dismiss(None)

    # ---------------------------------------------------------------- the app
    class MVMApp(App):
        TITLE = "multi-vpn-manager"
        CSS = """
        Screen { background: #1a1b26; color: #c0caf5; }
        #banner { height: 3; padding: 0 2; background: #16161e; border-bottom: heavy #7aa2f7; content-align: left middle; }
        TabbedContent { height: 1fr; }
        TabPane { padding: 1 1; }
        Tabs { background: #16161e; }
        Tab { color: #565f89; }
        Tab.-active { color: #7dcfff; text-style: bold; }
        Underline > .underline--bar { color: #bb9af7; background: #3b4261; }
        Footer { background: #16161e; }
        .card { border: round #3b4261; background: #24283b; padding: 0 1; height: auto; min-height: 8; }
        #dash-top { height: auto; }
        #dash-top > Static { width: 1fr; margin: 0 1 1 0; }
        DataTable { background: #1f2335; height: 1fr; border: round #3b4261; }
        DataTable > .datatable--header { background: #2f334d; color: #7aa2f7; text-style: bold; }
        DataTable > .datatable--cursor { background: #3d59a1; color: #ffffff; }
        DataTable:focus > .datatable--cursor { background: #7aa2f7; color: #1a1b26; }
        #vpn-side { width: 64; }
        #vpn-detail { width: 1fr; margin-left: 1; }
        .bar { height: 3; margin-top: 1; }
        .bar Button { margin-right: 1; min-width: 10; }
        #b-auto { width: 16; }
        #vpn-filter-row { height: 3; }
        #vpn-filter { width: 1fr; }
        #vpn-filter-row Label { margin: 1 1 0 1; }
        #dash-events { border: round #3b4261; background: #24283b; padding: 0 1; height: auto; margin: 0 1 1 0; }
        #log-filter { width: 30; }
        #log-level { width: 22; }
        SelectionList { height: auto; max-height: 12; background: #1a1b26; border: round #3b4261; }
        Button { min-width: 10; }
        #log-top { height: 3; }
        #log-top Select { width: 40; }
        #log-top Label { margin: 1 1 0 2; }
        #doc-top { height: 3; }
        #doc-top Select { width: 36; margin-right: 1; }
        #doc-summary { height: 1; padding: 0 1; margin-bottom: 1; }
        #doc-detail { height: auto; min-height: 3; max-height: 8; border: round #3b4261; padding: 0 1; background: #24283b; }
        ModalScreen { align: center middle; background: #1a1b26 60%; }
        .modal { width: 80; height: auto; max-height: 94%; border: heavy #bb9af7; background: #24283b; padding: 1 2; overflow-y: auto; }
        .modal.wide { width: 104; }
        .modal.huge { width: 124; height: 90%; }
        .modal Label { color: #7aa2f7; margin-top: 1; }
        .modal-body { margin: 1 0; }
        .modal TextArea { height: 12; background: #1a1b26; }
        .buttons { height: 3; margin-top: 1; }
        .buttons Button { margin-right: 2; }
        .row { height: auto; }
        .row Input { width: 1fr; }
        .row Label.inline { margin: 1 1 0 0; }
        Input { background: #1a1b26; border: tall #3b4261; }
        Input:focus { border: tall #7dcfff; }
        RichLog { height: 1fr; background: #16161e; border: round #3b4261; }
        #settings-body Input { margin-bottom: 0; }
        #settings-body Label { color: #7aa2f7; margin-top: 1; }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("1", "tab('dashboard')", "Dashboard", show=False, priority=True),
            Binding("2", "tab('vpns')", "VPNs", show=False, priority=True),
            Binding("3", "tab('map')", "Map", show=False, priority=True),
            Binding("4", "tab('logs')", "Logs", show=False, priority=True),
            Binding("5", "tab('doctor')", "Troubleshoot", show=False, priority=True),
            Binding("6", "tab('settings')", "Settings", show=False, priority=True),
            Binding("u", "up", "Up"),
            Binding("d", "down", "Down"),
            Binding("t", "restart", "Restart"),
            Binding("p", "apply", "Apply routes"),
            Binding("e", "edit", "Edit"),
            Binding("s", "secrets", "Secrets"),
            Binding("a", "adopt", "Adopt"),
            Binding("n", "new_ssh", "New sshuttle"),
            Binding("o", "autostart", "Autostart"),
            Binding("l", "logs", "Logs"),
            Binding("v", "view_output", "Output"),
            Binding("h", "hide", "Hide"),
            Binding("f", "fix", "Fix"),
            Binding("g", "refresh_all", "Refresh"),
        ]

        def __init__(self) -> None:
            super().__init__()
            self.settings = load_settings()
            self.statuses: List[VpnStatus] = []
            self.foreign: List[Foreign] = []
            self.checks: List[Check] = []
            self.hist: Dict[str, collections.deque] = {}
            self.last_bytes: Dict[str, Tuple[float, int]] = {}
            self.tick = 0
            self.sel: Optional[str] = None
            self.log_name: Optional[str] = None
            self.log_pos = 0
            self._busy = threading.Lock()
            self.lat: Dict[str, collections.deque] = {}           # gateway / first-probe latency history
            self.prev_state: Dict[str, str] = {}
            self.busy: Dict[str, str] = {}                        # vpn -> running inline op ("connecting" ...)
            self.op_output: Dict[str, List[str]] = {}
            self.op_result: Dict[str, Optional[bool]] = {}
            self.op_done: Dict[str, float] = {}
            self.claims: Dict[str, List[str]] = {}
            self.owners: Dict[str, str] = {}
            self.spin_i = 0
            self.col_state: Any = None
            self.log_raw: List[Tuple[str, str]] = []              # (line, kind: hdr | own | journal)
            self.err_offsets: List[int] = []
            self.err_idx = -1

        def q(self, selector: str, expect: Any = None) -> Any:
            """look a widget up on the MAIN screen (self.query_one would search the open dialog instead)"""
            base = self.screen_stack[0]
            return base.query_one(selector, expect) if expect is not None else base.query_one(selector)

        def compose(self) -> ComposeResult:
            yield Static(Text("loading …", style=C_MUTED), id="banner")
            with TabbedContent(initial="dashboard"):
                with TabPane("◆ Dashboard", id="dashboard"):
                    with VerticalScroll():
                        with Horizontal(id="dash-top"):
                            yield Static("", id="dash-vpns", classes="card")
                            yield Static("", id="dash-foreign", classes="card")
                            yield Static("", id="dash-health", classes="card")
                        yield Static("", id="dash-table")
                        yield Static("", id="dash-events")
                        yield Static("", id="dash-cards")
                with TabPane("▤ VPNs", id="vpns"):
                    with Horizontal():
                        with Vertical(id="vpn-side"):
                            with Horizontal(id="vpn-filter-row"):
                                yield Input(placeholder="filter: name · type · state …", id="vpn-filter")
                                yield Label("hidden")
                                yield Switch(value=False, id="vpn-showhidden")
                            yield DataTable(id="vpn-table", cursor_type="row", zebra_stripes=True)
                            with Horizontal(classes="bar"):
                                yield Button("▶ Up", id="b-up", variant="success")
                                yield Button("■ Down", id="b-down", variant="error")
                                yield Button("Restart", id="b-restart", variant="warning")
                                yield Button("Apply", id="b-apply", variant="primary")
                            with Horizontal(classes="bar"):
                                yield Button("Edit", id="b-edit", variant="primary")
                                yield Button("Secrets", id="b-secrets")
                                yield Button("Adopt", id="b-adopt", variant="success")
                                yield Button("+ sshuttle", id="b-newssh")
                            with Horizontal(classes="bar"):
                                yield Button("Autostart", id="b-auto")
                                yield Button("Logs", id="b-logs")
                                yield Button("Check", id="b-check", variant="warning")
                                yield Button("Forget", id="b-del", variant="error")
                        with VerticalScroll(id="vpn-detail"):
                            yield Static("", id="vpn-detail-body")
                with TabPane("⇢ Routing map", id="map"):
                    with VerticalScroll():
                        yield Static("", id="graph")
                with TabPane("≡ Logs", id="logs"):
                    with Vertical():
                        with Horizontal(id="log-top"):
                            yield Select([], id="log-vpn", prompt="choose a VPN")
                            yield Input(placeholder="search …", id="log-filter")
                            yield Select([("all lines", "all"), ("warnings + errors", "warn"), ("errors only", "error")], value="all",
                                         allow_blank=False, id="log-level")
                            yield Label("journal")
                            yield Switch(value=True, id="log-journal")
                            yield Button("Next error", id="log-next", variant="error")
                            yield Button("Reload", id="log-reload", variant="primary")
                        yield RichLog(id="log-view", markup=False, wrap=True, highlight=False, max_lines=5000)
                with TabPane("✚ Troubleshoot", id="doctor"):
                    with Vertical():
                        with Horizontal(id="doc-top"):
                            yield Select([("everything", "*")], value="*", allow_blank=False, id="doc-scope")
                            yield Button("Quick check", id="doc-quick", variant="primary")
                            yield Button("Deep check", id="doc-deep", variant="warning")
                            yield Button("Fix selected", id="doc-fix", variant="success")
                            yield Button("Install sudoers", id="doc-sudo")
                        yield Static("", id="doc-summary")
                        yield DataTable(id="doc-table", cursor_type="row", zebra_stripes=True)
                        yield Static("", id="doc-detail")
                with TabPane("⚙ Settings", id="settings"):
                    with VerticalScroll(id="settings-body"):
                        yield Label("Refresh interval (seconds)")
                        yield Input(id="set-refresh_interval", type="integer")
                        yield Label("NetworkManager connect timeout (seconds)")
                        yield Input(id="set-connect_timeout", type="integer")
                        yield Label("Routing tables cleaned of /32 exclusions for our IPs (comma separated) — e.g. main, windscribe")
                        yield Input(id="set-clean_tables")
                        yield Label("Journal window for logs (minutes)")
                        yield Input(id="set-journal_minutes", type="integer")
                        yield Label("Add `to IP lookup main` policy rules (prio %d) so other VPNs' policy routing can't steal our IPs" % RULE_PRIO)
                        yield Switch(id="set-policy_rules")
                        yield Label("Colours (applies on next start; 'auto' = true colour unless on a Linux console)")
                        yield Select([("auto", "auto"), ("true colour (24-bit)", "truecolor"), ("256 colours", "256"), ("16 colours", "16")],
                                     value="auto", allow_blank=False, id="set-colors")
                        yield Label("Health probe interval (seconds)")
                        yield Input(id="set-probe_interval", type="integer")
                        yield Label("Re-resolve hostnames in route lists every … seconds (changed IPs are re-applied automatically)")
                        yield Input(id="set-dns_refresh", type="integer")
                        yield Label("Desktop notifications (drops, lost routes, failing probes, recoveries) — can be turned off per VPN in Edit")
                        yield Switch(id="set-notifications")
                        yield Label("Up / down progress")
                        yield Select([("inline in the VPN row (press v for the output)", "inline"), ("popup with the live log", "popup")],
                                     value="inline", allow_blank=False, id="set-op_view")
                        with Horizontal(classes="bar"):
                            yield Button("Save settings", id="s-save", variant="success")
                            yield Button("Install sudoers rule", id="s-sudo", variant="warning")
                            yield Button("Export configs…", id="s-export", variant="primary")
                            yield Button("Import configs…", id="s-import", variant="primary")
                        yield Static("", id="sudoers-preview")
            yield Footer()

        # ---- lifecycle
        def on_mount(self) -> None:
            t = self.q("#vpn-table", DataTable)
            for label, w in (("VPN", 20), ("Type", 10), ("State", 13), ("If", 6), ("Routes", 7)):
                k = t.add_column(label, width=w)
                if label == "State":
                    self.col_state = k
            d = self.q("#doc-table", DataTable)
            for label, w in (("", 2), ("Group", 18), ("Check", 28), ("Result", 64)):
                d.add_column(label, width=w)
            self.load_settings_form()
            self.live_refresh()
            self.run_doctor_bg(False)
            self.set_interval(max(1, int(self.settings.get("refresh_interval", 3))), self.live_refresh)
            self.set_interval(2.0, self.poll_log)
            self.set_interval(max(5, int(self.settings.get("probe_interval", 15))), self.probe_refresh)
            self.set_interval(60, self.dns_watch)
            self.set_interval(0.25, self.spin)
            self.set_timer(2.5, self.probe_refresh)

        def check_action(self, action: str, parameters: Tuple[Any, ...]) -> Optional[bool]:
            if len(self.screen_stack) > 1:
                return action not in ("tab", "up", "down", "restart", "apply", "edit", "secrets", "adopt", "new_ssh", "autostart", "logs", "fix",
                                      "hide", "view_output") or None
            if action == "tab" and isinstance(self.focused, (Input, Select, TextArea)):
                return False
            return True

        def action_tab(self, name: str) -> None:
            self.set_focus(None)
            self.q(TabbedContent).active = name

        def action_refresh_all(self) -> None:
            self.live_refresh(True)
            self.notify("refreshing …", timeout=1.2)

        # ---- live data
        @work(thread=True, exclusive=True, group="live")
        def live_refresh(self, deep: bool = False) -> None:
            if not self._busy.acquire(blocking=False):
                return
            try:
                sts = collect_status(True)
                deep = deep or self.tick % 5 == 0
                fs = detect_foreign(own_ifaces(sts), deep=deep) if deep else self._merge_foreign(detect_foreign(own_ifaces(sts), deep=False))
                self.tick += 1
                self.call_from_thread(self.apply_live, sts, fs)
            except Exception as e:  # noqa: BLE001
                self.call_from_thread(self.notify, "refresh error: %r" % e, severity="error")
            finally:
                self._busy.release()

        def _merge_foreign(self, quick: List[Foreign]) -> List[Foreign]:
            """keep vendor-CLI results from the last deep scan (they are slow), update the rest"""
            deep = {f.name: f for f in self.foreign if f.state in ("connected", "disconnected") and f.detail}
            out = []
            for f in quick:
                d = deep.pop(f.name, None)
                if d and f.state in ("running", "present"):   # vendor CLI knows better than "process exists"
                    f.state, f.detail = d.state, d.detail
                out.append(f)
            return out + list(deep.values())

        def apply_live(self, sts: List[VpnStatus], fs: List[Foreign]) -> None:
            self.statuses, self.foreign = sts, fs
            self.claims = collections.defaultdict(list)
            for s_ in sts:
                for r in expand_routes((s_.cfg or {}).get("routes", [])):
                    self.claims[r].append(s_.name)
            self.owners = route_owners(sts)
            self.detect_transitions(sts)
            t0 = time.time()
            for s in sts:
                tot = s.rx + s.tx
                prev = self.last_bytes.get(s.name)
                if s.iface and prev and tot >= prev[1]:
                    self.hist.setdefault(s.name, collections.deque(maxlen=60)).append((tot - prev[1]) / max(t0 - prev[0], 0.5))
                self.last_bytes[s.name] = (t0, tot)
            self.q("#banner", Static).update(render_banner(sts, fs))
            self.update_dashboard()
            self.update_vpn_table()
            self.q("#graph", Static).update(render_graph(sts, fs))
            self.update_log_choices()
            self.update_doc_scope()

        def detect_transitions(self, sts: List[VpnStatus]) -> None:
            """state changes NOT caused by our own up/down -> event timeline + desktop notification"""
            for s_ in sts:
                if not s_.configured:
                    continue
                prev = self.prev_state.get(s_.name)
                self.prev_state[s_.name] = s_.state
                if prev is None or prev == s_.state or s_.name in self.busy or now() - self.op_done.get(s_.name, 0) < 20:
                    continue
                n = s_.name
                if prev in UP_STATES and s_.state in ("down", "missing"):
                    event(n, "dropped", "tunnel dropped (%s → %s)" % (prev, s_.state))
                    desktop_notify("%s dropped" % n, "the tunnel went down — its routes now fall back to your normal connection", "critical", n)
                elif s_.state == "partial" and prev in ("up", "degraded"):
                    bad = [short_route(r.dst) for r in s_.routes if not r.ok and not r.owner]
                    event(n, "lost", "%d route(s) no longer via %s: %s" % (len(bad), s_.iface, ", ".join(bad[:4])))
                    desktop_notify("%s lost routes" % n, "%d IP(s) no longer go through %s — press p to re-apply" % (len(bad), s_.iface), "normal", n)
                elif s_.state == "degraded" and prev == "up":
                    bad = [p_.target for p_ in s_.probes if not p_.ok]
                    event(n, "probe", "probe failing: %s" % ", ".join(bad[:3]))
                    desktop_notify("%s: target unreachable" % n, "tunnel is up but %s does not answer" % ", ".join(bad[:3]), "normal", n)
                elif s_.state == "up" and prev in ("partial", "degraded"):
                    event(n, "recovered", "healthy again (was %s)" % prev)
                    desktop_notify("%s recovered" % n, "all routes and probes OK again", "low", n)
                elif s_.state in UP_STATES and prev in ("down", "activating", "missing"):
                    event(n, "up", "came up outside mvm (GUI / autostart)")

        @work(thread=True, exclusive=True, group="probes")
        def probe_refresh(self) -> None:
            sts = list(self.statuses)
            try:
                probe_round(sts)
                for s_ in sts:
                    if s_.state not in UP_STATES or not (s_.gw or (s_.cfg or {}).get("probes")):
                        continue   # nothing to measure (e.g. sshuttle without probes)
                    ms = ping(s_.gw, 1) if s_.gw else None
                    if ms is None and s_.cfg and s_.cfg.get("probes"):
                        pr = next((x for x in load_probe_results(s_.name) if x.ok and x.ms is not None), None)
                        ms = pr.ms if pr else None
                    self.lat.setdefault(s_.name, collections.deque(maxlen=40)).append(ms)
            except Exception as e:  # noqa: BLE001
                self.call_from_thread(self.notify, "probe error: %r" % e, severity="error")
            self.call_from_thread(self.live_refresh)

        @work(thread=True, exclusive=True, group="dns")
        def dns_watch(self) -> None:
            """hostnames in route lists: re-resolve; if the IPs changed, re-apply the routes of that VPN"""
            for s_ in list(self.statuses):
                if not s_.cfg or s_.state not in UP_STATES or s_.name in self.busy or not host_entries(s_.cfg.get("routes", [])):
                    continue
                ch = dns_changed(s_.cfg)
                if not ch:
                    continue
                added, gone = len(ch[1] - ch[0]), len(ch[0] - ch[1])
                if s_.kind == "sshuttle":
                    event(s_.name, "dns", "hostname IPs changed (+%d −%d) — restart sshuttle to use them" % (added, gone))
                    desktop_notify("%s: hostname IPs changed" % s_.name, "restart it (t) so sshuttle routes the new IPs", "normal", s_.name)
                    continue
                connect(s_.cfg, self.settings, None)
                event(s_.name, "dns", "hostname IPs changed → routes re-applied (+%d −%d)" % (added, gone))
                self.op_done[s_.name] = now()
            self.call_from_thread(self.live_refresh)

        def spin(self) -> None:
            if not self.busy or self.col_state is None:
                return
            self.spin_i += 1
            t = self.q("#vpn-table", DataTable)
            for name, what in list(self.busy.items()):
                try:
                    t.update_cell(name, self.col_state, Text("%s %s" % ("◐◓◑◒"[self.spin_i % 4], what), style="bold " + C_CYAN))
                except Exception:  # noqa: BLE001  (row filtered out / not there yet)
                    pass

        def visible_statuses(self, for_dashboard: bool = False) -> List[VpnStatus]:
            hidden = set(self.settings.get("hidden_profiles", []))
            if for_dashboard:
                return [x for x in self.statuses if x.name not in hidden]
            show_hidden = self.q("#vpn-showhidden", Switch).value
            qtxt = self.q("#vpn-filter", Input).value.strip().lower()
            out = []
            for x in self.statuses:
                if x.name in hidden and not show_hidden:
                    continue
                hay = " ".join((x.name, x.display, KIND_LABEL.get(x.kind, x.kind), x.state, x.iface, "managed" if x.configured else "unmanaged")).lower()
                if qtxt and not all(w in hay for w in qtxt.split()):
                    continue
                out.append(x)
            return out

        def update_dashboard(self) -> None:
            sts = self.visible_statuses(for_dashboard=True)
            up = [s for s in sts if s.state in UP_STATES]
            v = Text()
            v.append("OUR VPNs\n\n", style="bold " + C_PURPLE)
            v.append("%d" % len(up), style="bold " + (C_GREEN if up else C_MUTED))
            v.append(" up  ·  %d managed  ·  %d in GUI not managed\n\n" % (sum(1 for s in sts if s.configured), sum(1 for s in sts if not s.configured)), style=C_MUTED)
            for s in sts:
                if s.configured or s.state != "down":
                    v.append_text(state_badge(s.state))
                    v.append("  %s\n" % s.name, style=C_TEXT)
            self.q("#dash-vpns", Static).update(v)
            self.q("#dash-foreign", Static).update(render_foreign(self.foreign, compact=True))
            self.update_health()
            self.q("#dash-table", Static).update(render_vpn_table(sts))
            ev = Text("RECENT EVENTS\n\n", style="bold " + C_PURPLE)
            ev.append_text(render_events(load_events(None, 40), with_vpn=True, limit=8))
            self.q("#dash-events", Static).update(ev)
            cards = []
            for s in up:
                cards.append(render_vpn_detail(s, list(self.hist.get(s.name, [])), list(self.lat.get(s.name, [])), load_events(s.name, 10),
                                               self.claims, self.owners, compact=True))
            self.q("#dash-cards", Static).update(Group(*cards) if cards else Text("\nno managed VPN is up — go to the VPNs tab (2) and press u", style=C_MUTED))

        def update_health(self) -> None:
            h = Text()
            h.append("HEALTH\n\n", style="bold " + C_PURPLE)
            if not self.checks:
                h.append("checking …", style=C_MUTED)
            else:
                h.append_text(render_summary_line(doctor_summary(self.checks)))
                h.append("\n")
                for c in [c for c in self.checks if c.status == "fail"][:3] + [c for c in self.checks if c.status == "warn"][:2]:
                    ic, col = ICON[c.status]
                    h.append("\n%s %s: " % (ic, c.title), style="bold " + col)
                    h.append(c.detail[:70], style=C_MUTED)
            self.q("#dash-health", Static).update(h)

        def update_vpn_table(self) -> None:
            t = self.q("#vpn-table", DataTable)
            keep = self.sel
            t.clear()
            vis = self.visible_statuses()
            hidden = set(self.settings.get("hidden_profiles", []))
            for s in vis:
                routes = "%d/%d" % (s.routes_ok, len(s.routes)) if s.routes and s.state != "down" else str(len(expand_routes((s.cfg or {}).get("routes", [])))) if s.cfg else "-"
                name = Text(s.name, style="bold " + C_CYAN) if s.configured else Text(s.name + " ·", style=C_MUTED)
                if s.name in hidden:
                    name = Text(s.name + " (hidden)", style="italic " + C_MUTED)
                st_cell = Text("%s %s" % ("◐◓◑◒"[self.spin_i % 4], self.busy[s.name]), style="bold " + C_CYAN) if s.name in self.busy else state_badge(s.state)
                t.add_row(name, KIND_LABEL.get(s.kind, s.kind), st_cell, s.iface or ("ssh" if s.pid else "-"), routes, key=s.name)
            if vis:
                names = [s.name for s in vis]
                idx = names.index(keep) if keep in names else 0
                t.move_cursor(row=idx)
                self.sel = names[idx]
            self.update_detail()

        def update_autostart_button(self, s: Optional[VpnStatus] = None) -> None:
            """red 'Autostart ON' when the selected VPN starts at login, plain 'Autostart' otherwise"""
            s = s if s is not None else self.cur()
            b = self.q("#b-auto", Button)
            on_ = bool(s and s.configured and s.autostart)
            b.label = "Autostart ON" if on_ else "Autostart"
            b.variant = "error" if on_ else "default"
            b.tooltip = ("starts at login — press to disable" if on_ else "press to start this VPN at login") if s and s.configured else "adopt the VPN first"

        def update_detail(self) -> None:
            s = self.cur()
            self.update_autostart_button(s)
            body = self.q("#vpn-detail-body", Static)
            if not s:
                body.update(Text("no VPNs found. Create one in the GUI (NetworkManager) or add an sshuttle profile (n).", style=C_MUTED))
                return
            parts: List[Any] = [render_vpn_detail(s, list(self.hist.get(s.name, [])), list(self.lat.get(s.name, [])), load_events(s.name, 20),
                                                  self.claims, self.owners)]
            if s.name in self.busy:
                parts.insert(0, Text("◌ %s … (press v to watch the output)" % self.busy[s.name], style="bold " + C_CYAN))
            if not s.configured:
                parts.append(Text("\nThis GUI VPN is not managed yet. Press a (Adopt) to give it routes, logs and autostart.", style=C_YELLOW))
            elif s.cfg:
                iss = validate_config(s.cfg, [x.cfg for x in self.statuses if x.cfg])
                if iss:
                    parts.append(Panel(render_issues(iss), title="config", border_style=C_MUTED, box=box.ROUNDED))
            body.update(Group(*parts))

        def cur(self) -> Optional[VpnStatus]:
            return next((s for s in self.statuses if s.name == self.sel), None)

        @on(Input.Changed, "#vpn-filter")
        @on(Switch.Changed, "#vpn-showhidden")
        def _vfilter(self) -> None:
            self.update_vpn_table()

        def action_hide(self) -> None:
            s = self.cur()
            if not s:
                return
            hidden = list(self.settings.get("hidden_profiles", []))
            if s.name in hidden:
                hidden.remove(s.name)
                msg = "%s is visible again" % s.name
            else:
                hidden.append(s.name)
                msg = "hid %s — switch on 'hidden' above the list to see it (h again to unhide)" % s.name
            self.settings["hidden_profiles"] = hidden
            st = load_settings()
            st["hidden_profiles"] = hidden
            save_settings(st)
            self.notify(msg, timeout=4)
            self.update_vpn_table()
            self.update_dashboard()

        @on(DataTable.RowHighlighted, "#vpn-table")
        def _row(self, ev: DataTable.RowHighlighted) -> None:
            if ev.row_key and ev.row_key.value:
                self.sel = str(ev.row_key.value)
                self.update_detail()

        # ---- actions on the selected VPN
        def _cfg_or_warn(self) -> Optional[Dict[str, Any]]:
            s = self.cur()
            if not s:
                self.notify("select a VPN first (tab 2)", severity="warning")
                return None
            if not s.configured or not s.cfg:
                self.notify("%s is not managed yet — press a to adopt it" % s.name, severity="warning")
                return None
            return s.cfg

        def run_op(self, title: str, job: Callable[[Callable[[str], None]], bool], name: Optional[str] = None, what: str = "working") -> None:
            if not name or self.settings.get("op_view", "inline") == "popup":
                self.push_screen(RunLog(title, job), lambda _: self.live_refresh(True))
                return
            if name in self.busy:
                self.notify("%s is busy (%s) — press v to watch" % (name, self.busy[name]), severity="warning")
                return
            self.busy[name] = what
            self.op_output[name] = []
            self.op_result[name] = None
            self.update_vpn_table()
            out = self.op_output[name]

            def runner() -> None:
                try:
                    ok = bool(job(out.append))
                except Exception as e:  # noqa: BLE001
                    out.append("✖ internal error: %r" % e)
                    ok = False
                self.call_from_thread(self._op_done, name, title, ok)
            threading.Thread(target=runner, daemon=True).start()

        def _op_done(self, name: str, title: str, ok: bool) -> None:
            self.busy.pop(name, None)
            self.op_done[name] = now()
            self.op_result[name] = ok
            if ok:
                self.notify("✔ %s" % title, timeout=4)
            else:
                last = next((l for l in reversed(self.op_output.get(name, [])) if l.startswith(("✖", "⚠"))), "")
                self.notify("✖ %s failed — press v for the output\n%s" % (title, last[:140]), severity="error", timeout=12)
            self.live_refresh(True)

        def action_view_output(self) -> None:
            name = self.sel
            if not name or name not in self.op_output:
                self.notify("no up/down output for %s yet in this session (see Logs: l)" % (name or "-"), severity="warning")
                return

            def follow(say: Callable[[str], None]) -> bool:
                i = 0
                while True:
                    lines = self.op_output.get(name, [])
                    while i < len(lines):
                        say(lines[i])
                        i += 1
                    if name not in self.busy:
                        return bool(self.op_result.get(name))
                    time.sleep(0.2)
            self.push_screen(RunLog("Output: %s" % name, follow))

        def action_up(self) -> None:
            c = self._cfg_or_warn()
            if c:
                self.run_op("Up: %s" % c["name"], lambda say: connect(c, self.settings, say), c["name"], "connecting")

        def action_down(self) -> None:
            c = self._cfg_or_warn()
            if c:
                self.run_op("Down: %s" % c["name"], lambda say: disconnect(c, self.settings, say), c["name"], "stopping")

        def action_restart(self) -> None:
            c = self._cfg_or_warn()
            if c:
                self.run_op("Restart: %s" % c["name"], lambda say: (disconnect(c, self.settings, say), connect(c, self.settings, say))[1], c["name"], "restarting")

        def action_apply(self) -> None:
            c = self._cfg_or_warn()
            if not c:
                return
            if c["kind"] == "sshuttle":
                self.notify("sshuttle takes its routes at start: use Restart (t)", severity="warning")
                return
            s = self.cur()
            if s and s.state not in UP_STATES:
                self.notify("%s is down — Up (u) applies the routes" % c["name"], severity="warning")
                return
            self.run_op("Apply routes: %s" % c["name"], lambda say: connect(c, self.settings, say), c["name"], "applying")

        def action_edit(self) -> None:
            c = self._cfg_or_warn()
            if not c:
                return
            others = [x.cfg for x in self.statuses if x.cfg and x.name != c["name"]]

            def done(v: Optional[Dict[str, Any]]) -> None:
                if v:
                    save_config(v)
                    vlog(v["name"], "config edited (%d routes)" % len(v["routes"]))
                    event(v["name"], "config", "config edited · %d route entr%s · %d probe(s)" % (len(v["routes"]), "y" if len(v["routes"]) == 1 else "ies",
                                                                                               len(v.get("probes") or [])))
                    s = self.cur()
                    self.notify("saved %s%s" % (v["name"], " — press p to apply to the running tunnel" if s and s.state in UP_STATES else ""), timeout=4)
                    self.live_refresh()
            self.push_screen(ConfigForm(c, others), done)

        def action_adopt(self) -> None:
            s = self.cur()
            if not s or s.configured or not s.nm:
                self.notify("select a GUI VPN marked 'not managed' to adopt it", severity="warning")
                return
            c = default_config(slug(s.nm.name), s.nm.kind)
            c.update({"nm_uuid": s.nm.uuid, "nm_name": s.nm.name})
            others = [x.cfg for x in self.statuses if x.cfg]

            def done(v: Optional[Dict[str, Any]]) -> None:
                if v:
                    save_config(v)
                    vlog(v["name"], "adopted GUI profile %s" % s.nm.name)
                    self.sel = v["name"]
                    self.notify("adopted %s" % v["name"])
                    self.live_refresh()
            self.push_screen(ConfigForm(c, others, is_new=True), done)

        def action_new_ssh(self) -> None:
            c = default_config("sshuttle-%d" % (1 + sum(1 for s in self.statuses if s.kind == "sshuttle")), "sshuttle")
            others = [x.cfg for x in self.statuses if x.cfg]

            def done(v: Optional[Dict[str, Any]]) -> None:
                if v:
                    save_config(v)
                    vlog(v["name"], "sshuttle profile created")
                    self.sel = v["name"]
                    self.live_refresh()
            self.push_screen(ConfigForm(c, others, is_new=True), done)

        def action_secrets(self) -> None:
            c = self._cfg_or_warn()
            if not c:
                return
            s = self.cur()
            if not s or not s.nm:
                self.notify("only NetworkManager VPNs have stored secrets (sshuttle uses your SSH keys)", severity="warning")
                return
            prof = s.nm
            stored, _ = nm_secret_keys_stored(prof.uuid)

            def done(vals: Optional[Dict[str, str]]) -> None:
                if not vals:
                    return
                ok, msg = nm_set_secrets(prof.uuid, vals, use_sudo="auto")
                if not ok:
                    with self.suspend():
                        print("NetworkManager refused the change as your user (%s).\nRetrying with sudo:" % msg)
                        ok, msg = nm_set_secrets(prof.uuid, vals, use_sudo="interactive")
                vlog(c["name"], "secrets updated: %s (%s)" % (", ".join(sorted(vals)), "ok" if ok else "failed"))
                self.notify(("✔ " if ok else "✖ ") + msg, severity="information" if ok else "error", timeout=6)
                self.live_refresh()
                self.run_doctor_bg(False)
            self.push_screen(SecretsForm(prof, stored), done)

        def action_autostart(self) -> None:
            c = self._cfg_or_warn()
            if not c:
                return
            on_ = not autostart_enabled(c["name"])
            ok, msg = set_autostart(c["name"], on_)
            self.notify(("autostart %s for %s" % ("enabled" if on_ else "disabled", c["name"])) if ok else "✖ " + msg,
                        severity="information" if ok else "error", timeout=5)
            s = self.cur()
            if ok and s:
                s.autostart = on_
                self.update_autostart_button(s)   # instant feedback, before the next refresh
            self.live_refresh()

        def action_logs(self) -> None:
            s = self.cur()
            if s and s.configured:
                self.q("#log-vpn", Select).value = s.name
            self.action_tab("logs")

        def forget(self) -> None:
            c = self._cfg_or_warn()
            if not c:
                return

            def done(ok: Optional[bool]) -> None:
                if ok:
                    if load_state(c["name"]):
                        disconnect(c, self.settings, None)
                    if autostart_enabled(c["name"]):
                        set_autostart(c["name"], False)
                    delete_config(c["name"])
                    self.notify("forgot %s (config kept as .deleted; GUI profile untouched)" % c["name"])
                    self.live_refresh()
            self.push_screen(Confirm("Forget %s?" % c["name"], Text("Stops it if running, removes our routes and autostart, renames the config to .json.deleted.\n"
                                                                   "The NetworkManager profile itself is NOT deleted.", style=C_MUTED), danger=True, yes="Forget"), done)

        @on(Button.Pressed)
        def _buttons(self, ev: Button.Pressed) -> None:
            bid = ev.button.id or ""
            m = {"b-up": self.action_up, "b-down": self.action_down, "b-restart": self.action_restart, "b-apply": self.action_apply,
                 "b-edit": self.action_edit, "b-secrets": self.action_secrets, "b-adopt": self.action_adopt, "b-newssh": self.action_new_ssh,
                 "b-auto": self.action_autostart, "b-logs": self.action_logs, "b-del": self.forget,
                 "b-check": lambda: self.check_selected(), "log-reload": lambda: self.load_log(True),
                 "doc-quick": lambda: self.run_doctor_bg(False), "doc-deep": lambda: self.run_doctor_bg(True), "doc-fix": self.action_fix,
                 "doc-sudo": self.install_sudo, "s-sudo": self.install_sudo, "s-save": self.save_settings_form,
                 "s-export": self.export_dialog, "s-import": self.import_dialog, "log-next": self.next_error}
            if bid in m:
                m[bid]()

        def check_selected(self) -> None:
            s = self.cur()
            if s and s.configured:
                self.q("#doc-scope", Select).value = s.name
            self.action_tab("doctor")
            self.run_doctor_bg(True)

        # ---- logs tab
        def update_log_choices(self) -> None:
            sel = self.q("#log-vpn", Select)
            names = [s.name for s in self.statuses if s.configured]
            opts = [(n, n) for n in names]
            if getattr(self, "_log_opts", None) != opts:
                self._log_opts = opts
                cur = sel.value
                sel.set_options(opts)
                if cur in names:
                    sel.value = cur
                elif names and self.log_name is None:
                    sel.value = (self.sel if self.sel in names else names[0])

        @on(TabbedContent.TabActivated)
        def _tab_act(self, ev: TabbedContent.TabActivated) -> None:
            # RichLog wraps to its width at write time: re-render once the Logs tab is visible
            if ev.pane is not None and ev.pane.id == "logs" and self.log_name:
                self.load_log(True)

        @on(Select.Changed, "#log-vpn")
        def _logsel(self, ev: Select.Changed) -> None:
            if isinstance(ev.value, str):
                self.log_name = ev.value
                self.load_log(True)

        @on(Switch.Changed, "#log-journal")
        def _logj(self) -> None:
            self.load_log(True)

        @work(thread=True, exclusive=True, group="logs")
        def load_log(self, full: bool = True) -> None:
            name = self.log_name
            if not name:
                return
            c = find_config(name)
            own = tail_file(log_path(name), 400)
            jl = journal_lines(c, minutes=int(self.settings.get("journal_minutes", 180)), limit=300) if c and self.q("#log-journal", Switch).value else []
            p = log_path(name)
            pos = p.stat().st_size if p.exists() else 0
            self.call_from_thread(self.show_log, name, own, jl, pos)

        def show_log(self, name: str, own: List[str], jl: List[str], pos: int) -> None:
            raw: List[Tuple[str, str]] = [("── %s · own log (%s) ──" % (name, log_path(name)), "hdr")]
            raw += [(l, "own") for l in own] or [("(empty — the log fills when you use up/down/edit)", "hdr")]
            if self.q("#log-journal", Switch).value:
                raw.append(("── system journal: NetworkManager / VPN plugin lines for %s ──" % name, "hdr"))
                raw += [(l, "journal") for l in jl] or [("(no matching journal lines, or no permission to read the journal)", "hdr")]
            self.log_raw = raw
            self.log_pos = pos
            self.render_log()

        @staticmethod
        def line_level(l: str) -> str:
            if " ERROR " in l or (ERR_RX.search(l) and " INFO " not in l and " OK " not in l):
                return "error"
            if " WARN " in l or "<warn>" in l:
                return "warn"
            return "info"

        def log_passes(self, l: str, kind: str) -> bool:
            if kind == "hdr":
                return True
            lvl = self.q("#log-level", Select).value
            lv = self.line_level(l)
            if lvl == "error" and lv != "error" or lvl == "warn" and lv == "info":
                return False
            qtxt = self.q("#log-filter", Input).value.strip().lower()
            return not qtxt or qtxt in l.lower()

        def write_log_line(self, lg: Any, l: str, kind: str) -> None:
            if kind == "hdr":
                lg.write(Text(l, style="bold " + C_PURPLE if l.startswith("──") else C_MUTED))
                return
            t = self.style_line(l)
            qtxt = self.q("#log-filter", Input).value.strip()
            if qtxt:
                t.highlight_words([qtxt], style="bold #1a1b26 on " + C_YELLOW, case_sensitive=False)
            if self.line_level(l) == "error":
                self.err_offsets.append(len(lg.lines))
            lg.write(t)

        def render_log(self) -> None:
            lg = self.q("#log-view", RichLog)
            lg.clear()
            self.err_offsets, self.err_idx = [], -1
            shown = 0
            for l, kind in self.log_raw:
                if self.log_passes(l, kind):
                    self.write_log_line(lg, l, kind)
                    shown += kind != "hdr"
            if shown == 0 and (self.q("#log-filter", Input).value.strip() or self.q("#log-level", Select).value != "all"):
                lg.write(Text("(no lines match the filter)", style=C_MUTED))

        @on(Input.Changed, "#log-filter")
        @on(Select.Changed, "#log-level")
        def _logfilter(self) -> None:
            if self.log_raw:
                self.render_log()

        def next_error(self) -> None:
            if not self.err_offsets:
                self.notify("no errors in the shown lines", timeout=2)
                return
            self.err_idx = (self.err_idx + 1) % len(self.err_offsets)
            self.q("#log-view", RichLog).scroll_to(y=self.err_offsets[self.err_idx], animate=False)
            self.notify("error %d / %d" % (self.err_idx + 1, len(self.err_offsets)), timeout=1.5)

        def style_line(self, l: str) -> Text:
            if " ERROR " in l or ERR_RX.search(l) and " INFO " not in l:
                return Text(l, style=C_RED)
            if " WARN " in l:
                return Text(l, style=C_YELLOW)
            if "===" in l:
                return Text(l, style="bold " + C_CYAN)
            if " OK " in l:
                return Text(l, style=C_GREEN)
            return Text(l, style=C_TEXT)

        def poll_log(self) -> None:
            """follow the own log file while the Logs tab is open"""
            if not self.log_name or self.q(TabbedContent).active != "logs":
                return
            p = log_path(self.log_name)
            try:
                size = p.stat().st_size
            except OSError:
                return
            if size < self.log_pos:
                self.load_log(True)
                return
            if size > self.log_pos:
                with p.open() as f:
                    f.seek(self.log_pos)
                    new = f.read()
                    self.log_pos = f.tell()
                lg = self.q("#log-view", RichLog)
                for l in new.splitlines():
                    self.log_raw.append((l, "own"))
                    if self.log_passes(l, "own"):
                        self.write_log_line(lg, l, "own")

        # ---- troubleshoot tab
        def update_doc_scope(self) -> None:
            sel = self.q("#doc-scope", Select)
            opts = [("everything", "*")] + [(s.name, s.name) for s in self.statuses if s.configured]
            if getattr(self, "_doc_opts", None) != opts:
                self._doc_opts = opts
                cur = sel.value
                sel.set_options(opts)
                sel.value = cur if cur in [v for _, v in opts] else "*"

        @work(thread=True, exclusive=True, group="doctor")
        def run_doctor_bg(self, deep: bool) -> None:
            scope = self.q("#doc-scope", Select).value
            only = None if scope in ("*", Select.BLANK, None) else str(scope)
            self.call_from_thread(self.q("#doc-summary", Static).update, Text("checking%s …" % (" (deep: network, ssh)" if deep else ""), style="italic " + C_YELLOW))
            try:
                checks = run_doctor(self.settings, only, deep=deep)
            except Exception as e:  # noqa: BLE001
                checks = [Check("internal", "doctor", "fail", repr(e))]
            self.call_from_thread(self.show_doctor, checks, only is None)

        def show_doctor(self, checks: List[Check], full: bool) -> None:
            if full:
                self.checks = checks
                self.update_health()
            self.doc_rows = checks
            t = self.q("#doc-table", DataTable)
            t.clear()
            for i, c in enumerate(checks):
                ic, col = ICON[c.status]
                t.add_row(Text(ic, style="bold " + col), Text(c.group, style=C_PURPLE), c.title,
                          Text(c.detail[:120] + ("  [f: fix]" if c.fix else ""), style=col if c.status in ("fail", "warn") else C_MUTED), key=str(i))
            s = doctor_summary(checks)
            line = render_summary_line(s)
            line.append("   %d fixable — select a row and press f" % sum(1 for c in checks if c.fix), style=C_MUTED)
            self.q("#doc-summary", Static).update(line)
            bad = next((i for i, c in enumerate(checks) if c.status == "fail"), None)
            if bad is not None:
                t.move_cursor(row=bad)

        @on(DataTable.RowHighlighted, "#doc-table")
        def _docrow(self, ev: DataTable.RowHighlighted) -> None:
            rows = getattr(self, "doc_rows", [])
            try:
                c = rows[int(ev.row_key.value)]
            except (TypeError, ValueError, IndexError):
                return
            ic, col = ICON[c.status]
            t = Text()
            t.append("%s %s · %s\n" % (ic, c.group, c.title), style="bold " + col)
            t.append(c.detail + "\n", style=C_TEXT)
            if c.hint:
                t.append("→ " + c.hint, style=C_ORANGE)
            if c.fix:
                t.append("\n[f] apply fix: %s" % c.fix, style="bold " + C_GREEN)
            self.q("#doc-detail", Static).update(t)

        def action_fix(self) -> None:
            if self.q(TabbedContent).active != "doctor":
                self.check_selected()
                return
            rows = getattr(self, "doc_rows", [])
            t = self.q("#doc-table", DataTable)
            if not rows or t.cursor_row is None or t.cursor_row >= len(rows):
                return
            c = rows[t.cursor_row]
            if not c.fix:
                self.notify("no automatic fix for this one — follow the hint", severity="warning")
                return
            if c.fix == "sudoers":
                self.install_sudo()
                return
            if c.fix.startswith("secrets:"):
                self.sel = c.fix.split(":", 1)[1]
                self.action_secrets()
                return
            self.run_op("Fix: %s" % c.title, lambda say: apply_fix(c.fix, self.settings, say))
            self.run_doctor_bg(False)

        def install_sudo(self) -> None:
            with self.suspend():
                print("\n" + sudoers_text())
                print("Installing %s (sudo will ask for your password once):" % SUDOERS_FILE)
                ok, msg = install_sudoers(True)
                print(("✔ " if ok else "✖ ") + msg)
                time.sleep(1.2)
            self.notify(msg, severity="information" if ok else "error", timeout=6)
            self.run_doctor_bg(False)

        # ---- settings
        def load_settings_form(self) -> None:
            s = self.settings
            for k in ("refresh_interval", "connect_timeout", "journal_minutes"):
                self.q("#set-" + k, Input).value = str(s.get(k, ""))
            self.q("#set-clean_tables", Input).value = ", ".join(s.get("clean_tables", []))
            self.q("#set-policy_rules", Switch).value = bool(s.get("policy_rules", True))
            self.q("#set-colors", Select).value = s.get("colors", "auto") if s.get("colors", "auto") in ("auto", "truecolor", "256", "16") else "auto"
            for k in ("probe_interval", "dns_refresh"):
                self.q("#set-" + k, Input).value = str(s.get(k, ""))
            self.q("#set-notifications", Switch).value = bool(s.get("notifications", True))
            self.q("#set-op_view", Select).value = s.get("op_view", "inline") if s.get("op_view") in ("inline", "popup") else "inline"
            pv = Text("\nsudoers rule that `Install sudoers` writes to %s:\n" % SUDOERS_FILE, style="bold " + C_PURPLE)
            pv.append(sudoers_text(), style=C_MUTED)
            self.q("#sudoers-preview", Static).update(pv)

        def save_settings_form(self) -> None:
            s = dict(self.settings)
            for k in ("refresh_interval", "connect_timeout", "journal_minutes", "probe_interval", "dns_refresh"):
                v = self.q("#set-" + k, Input).value.strip()
                if v.isdigit() and int(v) > 0:
                    s[k] = int(v)
            s["clean_tables"] = [x.strip() for x in self.q("#set-clean_tables", Input).value.split(",") if x.strip()]
            s["policy_rules"] = self.q("#set-policy_rules", Switch).value
            cv = self.q("#set-colors", Select).value
            s["colors"] = cv if isinstance(cv, str) else "auto"
            s["notifications"] = self.q("#set-notifications", Switch).value
            ov = self.q("#set-op_view", Select).value
            s["op_view"] = ov if isinstance(ov, str) else "inline"
            s["hidden_profiles"] = self.settings.get("hidden_profiles", [])
            save_settings(s)
            self.settings = s
            self.notify("settings saved (refresh / probe intervals apply after restart)")

        def export_dialog(self) -> None:
            names = [x["name"] for x in load_configs() if not x.get("broken")]
            if not names:
                self.notify("no managed VPNs to export", severity="warning")
                return

            def done(v: Optional[Dict[str, Any]]) -> None:
                if not v:
                    return
                data = export_bundle(v["names"], v["strip_routes"], v["strip_hosts"])
                try:
                    out = Path(v["path"]).expanduser()
                    atomic_write(out, json.dumps(data, indent=2) + "\n")
                    self.notify("✔ exported %d VPN config(s) to %s" % (len(data["vpns"]), out), timeout=6)
                except OSError as e:
                    self.notify("✖ %s" % e, severity="error")
            self.push_screen(ExportForm(names), done)

        def import_dialog(self) -> None:
            def done(v: Optional[Dict[str, Any]]) -> None:
                if not v:
                    return
                try:
                    res = import_bundle(json.loads(Path(v["path"]).expanduser().read_text()), v["overwrite"])
                except (OSError, ValueError) as e:
                    self.notify("✖ %s" % e, severity="error")
                    return
                body = Text()
                for n, what in res:
                    body.append("%s %-20s %s\n" % ("·" if what.startswith("skipped") else "✔", n, what),
                                style=C_MUTED if what.startswith("skipped") else C_GREEN)
                self.push_screen(Confirm("Import result", body, yes="OK"))
                self.live_refresh(True)
            self.push_screen(ImportForm(), done)

    return MVMApp()


def run_tui() -> int:
    make_app().run()
    return 0


# ======================================================================================
# 14. entry point
# ======================================================================================
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="mvm", description="Multi-VPN Manager (run without arguments for the TUI)")
    ap.add_argument("--colors", choices=["auto", "truecolor", "256", "16"])
    ap.add_argument("--pause", action="store_true", help="wait for Enter before exiting (for desktop launchers)")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("list", help="GUI VPNs + managed profiles")
    st = sub.add_parser("status", help="status + analysis of all VPNs")
    st.add_argument("name", nargs="?")
    st.add_argument("--watch", action="store_true")
    st.add_argument("--json", action="store_true")
    for n, h in (("up", "connect + apply routes"), ("down", "remove routes + disconnect"), ("restart", "down then up"),
                 ("apply", "re-apply routes to a running VPN"), ("delete", "forget a managed VPN (GUI profile untouched)"),
                 ("secrets", "store the VPN credentials in the GUI profile")):
        p = sub.add_parser(n, help=h)
        p.add_argument("name")
        if n == "up":
            p.add_argument("--retries", type=int, default=0)
    r = sub.add_parser("routes", help="list/add/rm/import/clear routes of a VPN")
    r.add_argument("name")
    r.add_argument("action", nargs="?", choices=["list", "add", "rm", "import", "clear"])
    r.add_argument("items", nargs="*")
    a = sub.add_parser("adopt", help="manage a GUI (NetworkManager) VPN")
    a.add_argument("profile")
    a.add_argument("--name")
    a.add_argument("--routes-file", action="append")
    a.add_argument("--gateway")
    ns = sub.add_parser("new-sshuttle", help="create an sshuttle profile")
    ns.add_argument("name")
    ns.add_argument("--remote", required=True)
    ns.add_argument("--routes-file", action="append")
    ns.add_argument("--ssh-args")
    d = sub.add_parser("doctor", help="troubleshoot (works without packages)")
    d.add_argument("name", nargs="?")
    d.add_argument("--deep", action="store_true", help="also test servers, ssh logins, gateway pings")
    d.add_argument("--fix", action="store_true", help="apply the available fixes")
    d.add_argument("--json", action="store_true")
    lg = sub.add_parser("logs", help="show the log of a VPN")
    lg.add_argument("name")
    lg.add_argument("-n", type=int, default=80)
    lg.add_argument("-f", "--follow", action="store_true")
    lg.add_argument("-j", "--journal", action="store_true", help="add NetworkManager / plugin journal lines")
    pr = sub.add_parser("probes", help="health probes of a VPN: list | add T.. | rm T.. | run")
    pr.add_argument("name")
    pr.add_argument("action", nargs="?", choices=["list", "add", "rm", "run"])
    pr.add_argument("items", nargs="*", help="host:port · http(s)://url · ping:host")
    ex = sub.add_parser("export", help="export VPN configs (never secrets) to a JSON bundle")
    ex.add_argument("names", nargs="*", help="only these VPNs (default: all)")
    ex.add_argument("-o", "--output")
    ex.add_argument("--strip-routes", action="store_true", help="leave out routes and probes")
    ex.add_argument("--strip-hosts", action="store_true", help="leave out ssh remotes, hostnames and probes")
    im = sub.add_parser("import", help="import a bundle made by export")
    im.add_argument("file")
    im.add_argument("--overwrite", action="store_true", help="replace configs with the same name")
    dn = sub.add_parser("dns", help="resolve the hostnames in route lists now")
    dn.add_argument("name", nargs="?")
    sub.add_parser("graph", help="routing map")
    sub.add_parser("foreign", help="other VPNs on this machine")
    au = sub.add_parser("autostart", help="systemd --user autostart")
    au.add_argument("name")
    au.add_argument("state", choices=["on", "off"])
    su = sub.add_parser("sudoers", help="password-less ip/sshuttle rule")
    su.add_argument("action", nargs="?", default="install", choices=["install", "show", "check"])
    sub.add_parser("bootstrap", help="create .venv and install textual + rich")
    sub.add_parser("colors", help="show the colour mode + a true-colour test strip")
    args = ap.parse_args(argv)

    if os.geteuid() == 0 and args.cmd not in ("doctor", "sudoers") and os.environ.get("MVM_ALLOW_ROOT") != "1":
        print("Do not run mvm as root/sudo: NetworkManager secrets and SSH keys belong to your desktop user.\n"
              "Run it as yourself; privileged steps use `sudo -n` (set up once with: mvm sudoers install).")
        return 2
    configure_colors(args.colors or load_settings().get("colors", "auto"))
    for d_ in (CONFIGS, LOGS, STATE):
        d_.mkdir(parents=True, exist_ok=True)

    plain = {"doctor": cli_doctor, "bootstrap": cli_bootstrap, "up": cli_up, "down": cli_down, "restart": cli_restart, "apply": cli_apply,
             "routes": cli_routes, "adopt": cli_adopt, "new-sshuttle": cli_new_sshuttle, "delete": cli_delete, "secrets": cli_secrets,
             "logs": cli_logs, "autostart": cli_autostart, "sudoers": cli_sudoers, "list": cli_list, "foreign": cli_foreign, "status": cli_status,
             "probes": cli_probes, "export": cli_export, "import": cli_import, "dns": cli_dns}
    if args.cmd == "colors":
        reexec_into_venv_if_needed()
        return cli_colors(args)
    if args.cmd in ("graph",) or (args.cmd in ("list", "status", "foreign") and not can_import("rich")):
        reexec_into_venv_if_needed()
    if args.cmd == "graph":
        if not can_import("rich"):
            print("graph needs rich: python3 mvm.py bootstrap")
            return 1
        return cli_graph(args)
    if args.cmd in plain:
        return plain[args.cmd](args)

    # TUI
    reexec_into_venv_if_needed()
    if not (can_import("textual") and can_import("rich")):
        print("The TUI needs: %s" % ", ".join(REQ_PACKAGES))
        if sys.stdin.isatty():
            ans = input("Create %s and install them now? [Y/n] " % VENV_DIR.name).strip().lower()
            if ans in ("", "y", "yes") and bootstrap() and venv_python().exists():
                os.execve(str(venv_python()), [str(venv_python()), str(Path(__file__).resolve())] + sys.argv[1:], dict(os.environ, MVM_REEXEC="1"))
        print("Install them yourself:  python3 -m venv .venv && .venv/bin/pip install %s" % " ".join(REQ_PACKAGES))
        print("(all sub-commands except the TUI and graph keep working without them)")
        return 1
    return run_tui()


if __name__ == "__main__":
    try:
        rc = main()
        if "--pause" in sys.argv[1:] and sys.stdin.isatty():
            input("\npress Enter to close ")
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(130)
