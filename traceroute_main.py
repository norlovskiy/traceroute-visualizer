#!/usr/bin/env python3
"""
traceroute_main.py
==================
Entry point for the multi-probe traceroute tool.

Responsibilities covered here
------------------------------
  • Argument parsing  (argparse)
  • Input file parsing (.txt / .csv  →  list[str] of IPs)
  • Output file management
  • Outer execution loop  (per-IP dispatch → probe engine)

The actual probe logic (UDP / TCP / ICMP raw sockets) lives in
probe_engine.py, which this module imports and calls.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import logging
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Probe engine import (stub-safe: the engine module is owned by another dev).
# If it is not present yet, a helpful ImportError is raised at runtime, not
# at parse time, so argument --help still works during development.
# ---------------------------------------------------------------------------
def _load_probe_engine():
    try:
        import probe_engine  # type: ignore
        return probe_engine
    except ModuleNotFoundError:
        return None


# ===========================================================================
# 1. ARGUMENT PARSER
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    """
    Construct and return the CLI argument parser.

    All flags mirror classic traceroute conventions so the tool feels
    familiar, while extra flags support the multi-probe design.
    """
    parser = argparse.ArgumentParser(
        prog="traceroute_tool",
        description=(
            "Multi-probe traceroute: sends UDP, TCP, and ICMP probes at "
            "every hop for every target IP listed in the input file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  # Basic run with defaults
  sudo python traceroute_main.py targets.txt

  # Custom TTL range, 2 probe series per hop, 1-second inter-packet wait
  sudo python traceroute_main.py targets.csv -f 2 -m 20 -q 2 -w 1.0

  # Custom ports and 512-byte payload, results saved to run1.txt
  sudo python traceroute_main.py targets.txt -p 33434 --tcp-port 80 -s 512 -o run1.txt
""",
    )

    # --- Positional --------------------------------------------------------
    parser.add_argument(
        "target_file",
        metavar="TARGET_FILE",
        help="Path to a .txt or .csv file containing one IP address per line.",
    )

    # --- Probe-series count ------------------------------------------------
    parser.add_argument(
        "-q", "--queries",
        dest="queries",
        type=_positive_int,
        default=1,
        metavar="N",
        help=(
            "Number of probe *series* per hop. Each series consists of "
            "one UDP + one TCP + one ICMP packet. Default: 1."
        ),
    )

    # --- TTL range ---------------------------------------------------------
    parser.add_argument(
        "-f", "--first-ttl",
        dest="first_ttl",
        type=_ttl_value,
        default=1,
        metavar="TTL",
        help="Initial TTL (first hop to probe). Default: 1.",
    )
    parser.add_argument(
        "-m", "--max-ttl",
        dest="max_ttl",
        type=_ttl_value,
        default=30,
        metavar="TTL",
        help="Maximum TTL (last hop to probe). Default: 30.",
    )

    # --- Ports -------------------------------------------------------------
    parser.add_argument(
        "-p", "--port",
        dest="udp_port",
        type=_port_value,
        default=33434,
        metavar="PORT",
        help=(
            "Destination port used for UDP probes. "
            "Each successive probe increments this by 1. Default: 33434."
        ),
    )
    parser.add_argument(
        "--tcp-port",
        dest="tcp_port",
        type=_port_value,
        default=80,
        metavar="PORT",
        help="Destination port used for TCP SYN probes. Default: 80.",
    )

    # --- Packet size -------------------------------------------------------
    parser.add_argument(
        "-s", "--packet-size",
        dest="packet_size",
        type=_packet_size_value,
        default=60,
        metavar="BYTES",
        help=(
            "Total size (bytes) of each probe packet, including IP and "
            "transport headers. Minimum: 28 (IPv4 + UDP headers). Default: 60."
        ),
    )

    # --- Timing ------------------------------------------------------------
    parser.add_argument(
        "-w", "--wait",
        dest="wait",
        type=_non_negative_float,
        default=0.05,
        metavar="SECS",
        help=(
            "Wait time (seconds) between consecutive probe packets within "
            "a series. Default: 0.05."
        ),
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=_non_negative_float,
        default=3.0,
        metavar="SECS",
        help="Per-probe socket receive timeout in seconds. Default: 3.0.",
    )

    # --- Output ------------------------------------------------------------
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        metavar="FILE",
        help=(
            "Path to the output text file. Defaults to "
            "traceroute_<timestamp>.txt in the current directory."
        ),
    )

    # --- Verbosity ---------------------------------------------------------
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging to stderr.",
    )

    return parser


# ---------------------------------------------------------------------------
# Validator helpers (used as argparse 'type' callbacks)
# ---------------------------------------------------------------------------

def _positive_int(value: str) -> int:
    ivalue = int(value)
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"{value!r} must be ≥ 1.")
    return ivalue


def _ttl_value(value: str) -> int:
    ivalue = int(value)
    if not (1 <= ivalue <= 255):
        raise argparse.ArgumentTypeError(f"TTL {value!r} must be 1–255.")
    return ivalue


def _port_value(value: str) -> int:
    ivalue = int(value)
    if not (1 <= ivalue <= 65535):
        raise argparse.ArgumentTypeError(f"Port {value!r} must be 1–65535.")
    return ivalue


def _packet_size_value(value: str) -> int:
    ivalue = int(value)
    if ivalue < 28:
        raise argparse.ArgumentTypeError(
            f"Packet size {value!r} must be ≥ 28 bytes (IPv4 + UDP headers)."
        )
    return ivalue


def _non_negative_float(value: str) -> float:
    fvalue = float(value)
    if fvalue < 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be ≥ 0.")
    return fvalue


# ===========================================================================
# 2. FILE I/O
# ===========================================================================

# Regex that matches a bare IPv4 or IPv6 address (no CIDR notation).
_IP_RE = re.compile(
    r"^\s*"
    r"("
    r"(?:\d{1,3}\.){3}\d{1,3}"          # IPv4
    r"|"
    r"(?:[0-9a-fA-F]{0,4}:){2,7}"        # IPv6 (simplified)
    r"[0-9a-fA-F]{0,4}"
    r")"
    r"\s*$"
)


def _validate_ip(raw: str) -> str | None:
    """Return the IP string if valid, else None."""
    raw = raw.strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def parse_target_file(filepath: str | Path) -> list[str]:
    """
    Read *filepath* (.txt or .csv) and return a de-duplicated, ordered list
    of valid IP address strings.

    TXT format
    ----------
    One IP per line; blank lines and lines starting with ``#`` are ignored.

    CSV format
    ----------
    The first column of every data row is treated as the IP address.
    A header row is detected automatically (its first cell won't parse as an
    IP) and skipped.

    Parameters
    ----------
    filepath:
        Path to the input file.

    Returns
    -------
    list[str]
        Cleaned, de-duplicated list of IP strings in file order.

    Raises
    ------
    FileNotFoundError
        If *filepath* does not exist.
    ValueError
        If *filepath* has an unsupported extension.
    RuntimeError
        If the file contains no valid IP addresses.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")

    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv", ""}:
        raise ValueError(
            f"Unsupported file extension {suffix!r}. Use .txt or .csv."
        )

    ips: list[str] = []
    seen: set[str] = set()

    if suffix == ".csv":
        rows = _read_csv(path)
    else:
        rows = _read_txt(path)

    for candidate in rows:
        ip = _validate_ip(candidate)
        if ip and ip not in seen:
            ips.append(ip)
            seen.add(ip)
        elif candidate.strip() and not candidate.strip().startswith("#"):
            logging.warning("Skipping invalid or duplicate entry: %r", candidate.strip())

    if not ips:
        raise RuntimeError(
            f"No valid IP addresses found in {path}. "
            "Check the file format (one IP per line for .txt; IP in the "
            "first column for .csv)."
        )

    logging.info("Loaded %d unique target IP(s) from %s.", len(ips), path)
    return ips


def _read_txt(path: Path) -> Iterator[str]:
    """Yield candidate strings from a plain-text file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped


def _read_csv(path: Path) -> Iterator[str]:
    """Yield the first cell of every data row in a CSV file."""
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            cell = row[0].strip()
            if cell and not cell.startswith("#"):
                yield cell


# ---------------------------------------------------------------------------
# Output file helpers
# ---------------------------------------------------------------------------

def _default_output_path() -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"traceroute_{ts}.txt")


def open_output_file(path: str | Path | None) -> tuple[Path, "TextIO"]:
    """
    Open (or create) the output file for writing.

    Returns a ``(resolved_path, file_handle)`` tuple.  The caller is
    responsible for closing the handle.
    """
    resolved = Path(path) if path else _default_output_path()
    fh = open(resolved, "w", encoding="utf-8")
    logging.info("Output will be written to: %s", resolved.resolve())
    return resolved, fh


def write_header(fh, args: argparse.Namespace, targets: list[str]) -> None:
    """Write a human-readable run header to the output file."""
    sep = "=" * 72
    fh.write(f"{sep}\n")
    fh.write(f"  Multi-Probe Traceroute  —  {datetime.now().isoformat(timespec='seconds')}\n")
    fh.write(f"{sep}\n")
    fh.write(f"  Targets       : {len(targets)} IP(s)\n")
    fh.write(f"  TTL range     : {args.first_ttl} – {args.max_ttl}\n")
    fh.write(f"  Probe series  : {args.queries} per hop  (UDP + TCP + ICMP each)\n")
    fh.write(f"  UDP port base : {args.udp_port}\n")
    fh.write(f"  TCP port      : {args.tcp_port}\n")
    fh.write(f"  Packet size   : {args.packet_size} bytes\n")
    fh.write(f"  Inter-pkt wait: {args.wait} s\n")
    fh.write(f"  Socket timeout: {args.timeout} s\n")
    fh.write(f"{sep}\n\n")
    fh.flush()


def write_target_result(fh, target_ip: str, result: dict) -> None:
    """
    Write the structured result dict for one target to the output file.

    Expected ``result`` schema (produced by probe_engine):
    ::
        {
          "target": "1.2.3.4",
          "hops": [
            {
              "ttl": 1,
              "series": [
                {
                  "series_num": 1,
                  "probes": [
                    {"proto": "UDP", "src": "...", "rtt_ms": 1.23, "response": "..."},
                    {"proto": "TCP", ...},
                    {"proto": "ICMP", ...},
                  ]
                },
                ...
              ]
            },
            ...
          ]
        }

    Falls back to a raw repr() if the schema is unexpected.
    """
    sep = "-" * 72
    fh.write(f"\n{'='*72}\n")
    fh.write(f"  Target: {target_ip}\n")
    fh.write(f"{'='*72}\n")

    hops = result.get("hops", [])
    if not hops:
        fh.write("  (no hops recorded)\n")
        fh.flush()
        return

    for hop in hops:
        ttl = hop.get("ttl", "?")
        fh.write(f"\n  Hop {ttl:>3}\n")
        fh.write(f"  {sep}\n")

        for series in hop.get("series", []):
            s_num = series.get("series_num", "?")
            fh.write(f"    Series #{s_num}\n")

            for probe in series.get("probes", []):
                proto   = probe.get("proto",    "?")
                src     = probe.get("src",      "*")
                rtt     = probe.get("rtt_ms",   None)
                resp    = probe.get("response", "*")
                rtt_str = f"{rtt:.3f} ms" if rtt is not None else "*"
                fh.write(
                    f"      [{proto:<4}]  src={src:<40}  rtt={rtt_str:<12}  {resp}\n"
                )

    fh.write("\n")
    fh.flush()


# ===========================================================================
# 3. MAIN LOOP
# ===========================================================================

def main() -> int:
    """
    Entry point: parse args → load targets → probe each target → write output.

    Returns an exit code (0 = success, non-zero = error).
    """
    parser  = build_parser()
    args    = parser.parse_args()

    # --- Logging setup -----------------------------------------------------
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        stream=sys.stderr,
        level=log_level,
        format="%(levelname)s  %(message)s",
    )

    # --- Validate TTL range ------------------------------------------------
    if args.first_ttl > args.max_ttl:
        parser.error(
            f"--first-ttl ({args.first_ttl}) must be ≤ --max-ttl ({args.max_ttl})."
        )

    # --- Root check (raw sockets require elevated privileges) --------------
    if os.name != "nt" and os.geteuid() != 0:
        logging.warning(
            "Raw socket operations typically require root / sudo. "
            "If probes fail with permission errors, re-run with sudo."
        )

    # --- Load probe engine -------------------------------------------------
    engine = _load_probe_engine()
    if engine is None:
        logging.error(
            "probe_engine.py not found. Place it in the same directory "
            "as traceroute_main.py and re-run."
        )
        return 2

    # --- Parse input file --------------------------------------------------
    try:
        targets = parse_target_file(args.target_file)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logging.error("Input file error: %s", exc)
        return 1

    # --- Open output file --------------------------------------------------
    try:
        out_path, out_fh = open_output_file(args.output_file)
    except OSError as exc:
        logging.error("Cannot open output file: %s", exc)
        return 1

    # --- Write run header --------------------------------------------------
    write_header(out_fh, args, targets)
    print(f"[+] Starting run — {len(targets)} target(s)  →  {out_path.resolve()}")

    # --- Outer loop: one iteration per target IP ---------------------------
    exit_code = 0
    for idx, target_ip in enumerate(targets, start=1):
        print(f"\n[{idx}/{len(targets)}] Tracing {target_ip} …")
        logging.debug("Dispatching probe engine for target %s", target_ip)

        try:
            result = engine.trace(
                target      = target_ip,
                first_ttl   = args.first_ttl,
                max_ttl     = args.max_ttl,
                queries     = args.queries,
                udp_port    = args.udp_port,
                tcp_port    = args.tcp_port,
                packet_size = args.packet_size,
                wait        = args.wait,
                timeout     = args.timeout,
            )
        except PermissionError:
            logging.error(
                "Permission denied while probing %s — re-run with sudo.", target_ip
            )
            result = {"target": target_ip, "hops": [], "error": "PermissionError"}
            exit_code = 1
        except Exception as exc:                          # broad: engine may raise anything
            logging.error("Unexpected error for target %s: %s", target_ip, exc)
            result = {"target": target_ip, "hops": [], "error": str(exc)}
            exit_code = 1

        write_target_result(out_fh, target_ip, result)

        # Brief pause between targets to avoid flooding the network
        if idx < len(targets):
            time.sleep(args.wait)

    # --- Finalise ----------------------------------------------------------
    out_fh.write(f"\n{'='*72}\n  Run complete — {datetime.now().isoformat(timespec='seconds')}\n{'='*72}\n")
    out_fh.close()

    total = len(targets)
    print(f"\n[+] Done. Results written to {out_path.resolve()} ({total} target(s) processed).")
    return exit_code


# ===========================================================================
# Script entry
# ===========================================================================
if __name__ == "__main__":
    sys.exit(main())
