#!/usr/bin/env python3
"""
traceroute_main.py
==================
Entry point for the multi-probe traceroute tool.

Flow: parse args → init sender/receiver → probe each target → write JSON
"""

from __future__ import annotations 

import argparse
import csv
import ipaddress
import json
import logging
import os
import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Iterator

import packet_receiving as pr
from sender import init_sender, send_series


# ===========================================================================
# 1. ARGUMENT PARSER
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
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

  # Custom ports and 512-byte payload, results saved to run1.json
  sudo python traceroute_main.py targets.txt -p 33434 --tcp-port 80 -s 512 -o run1.json
""",
    )

    parser.add_argument(
        "target_file",
        metavar="TARGET_FILE",
        help="Path to a .txt or .csv file containing one IP address per line.",
    )
    parser.add_argument(
        "-q", "--queries",
        dest="queries",
        type=_positive_int,
        default=1,
        metavar="N",
        help="Number of probe series per hop (UDP + TCP + ICMP each). Default: 1.",
    )
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
    parser.add_argument(
        "-p", "--port",
        dest="udp_port",
        type=_port_value,
        default=33434,
        metavar="PORT",
        help="Destination port for UDP probes. Default: 33434.",
    )
    parser.add_argument(
        "--tcp-port",
        dest="tcp_port",
        type=_port_value,
        default=80,
        metavar="PORT",
        help="Destination port for TCP SYN probes. Default: 80.",
    )
    parser.add_argument(
        "-s", "--packet-size",
        dest="packet_size",
        type=_packet_size_value,
        default=60,
        metavar="BYTES",
        help="Total probe packet size in bytes (min 28). Default: 60.",
    )
    parser.add_argument(
        "-w", "--wait",
        dest="wait",
        type=_non_negative_float,
        default=0.05,
        metavar="SECS",
        help="Wait between consecutive probe packets within a series. Default: 0.05.",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=_non_negative_float,
        default=3.0,
        metavar="SECS",
        help="Seconds to wait for replies after the last probe. Default: 3.0.",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        default=None,
        metavar="FILE",
        help="Output JSON path. Defaults to traceroute_<timestamp>.json.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging to stderr.",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        default=False,
        help="Open the topology visualizer in the browser after the run.",
    )

    return parser


# ---------------------------------------------------------------------------
# Validators
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
# 2. FILE I/O — input
# ===========================================================================

def _validate_ip(raw: str) -> str | None:
    raw = raw.strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def parse_target_file(filepath: str | Path) -> list[str]:
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {path}")

    suffix = path.suffix.lower()
    if suffix not in {".txt", ".csv", ""}:
        raise ValueError(f"Unsupported file extension {suffix!r}. Use .txt or .csv.")

    ips: list[str] = []
    seen: set[str] = set()

    rows = _read_csv(path) if suffix == ".csv" else _read_txt(path)

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
            "Check the file format (one IP per line for .txt; IP in the first column for .csv)."
        )

    logging.info("Loaded %d unique target IP(s) from %s.", len(ips), path)
    return ips


def _read_txt(path: Path) -> Iterator[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                yield stripped


def _read_csv(path: Path) -> Iterator[str]:
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row:
                continue
            cell = row[0].strip()
            if cell and not cell.startswith("#"):
                yield cell


# ===========================================================================
# 3. JSON output
# ===========================================================================

def _default_output_path() -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"traceroute_{ts}.json")


def build_hop_entry(ttl: int, proto: str, entry: dict) -> dict:
    """
    Calculate aggregate stats from the raw samples list and return
    the final dict for one (ttl, protocol) entry.
    DNS lookup happens here, after all packets are captured, so it never
    blocks the sniffer's hot path.
    """
    samples  = entry["samples"]
    valid    = [s for s in samples if s is not None]
    avg_rtt  = round(sum(valid) / len(valid), 2) if valid else None
    loss_pct = round(samples.count(None) / len(samples) * 100, 1) if samples else 100.0

    router_ip = entry["router_ip"]
    hostname  = pr.resolve_hostname(router_ip) if router_ip != "*" else "*"

    return {
        "hop":        ttl,
        "protocol":   proto,
        "ip":         router_ip,
        "hostname":   hostname,
        "avg_rtt_ms": avg_rtt,
        "loss_pct":   loss_pct,
    }


def build_json_result(target_ip: str, hop_data: dict) -> dict:
    """
    Convert hop_data ({ttl: {proto: {router_ip, hostname, samples}}})
    into the output structure: {ttl_str: {proto: {...calculated fields...}}}
    """
    out = {}
    for ttl in sorted(hop_data.keys()):
        ttl_key = str(ttl)
        out[ttl_key] = {}
        for proto, entry in hop_data[ttl].items():
            out[ttl_key][proto] = build_hop_entry(ttl, proto, entry)
    return out


# ===========================================================================
# 4. VISUALIZER
# ===========================================================================

_TOPOLOGY_TEMPLATE = Path(__file__).parent / "topology (1).html"
_AUTOLOAD_MARKER   = 'window.addEventListener("load", () => {});'


def launch_visualizer(results: dict, json_path: Path) -> None:
    """Embed results into the topology HTML and open it in the default browser.

    Writes <json_stem>.html alongside the JSON file so it can be reopened later.
    """
    if not _TOPOLOGY_TEMPLATE.exists():
        logging.warning("Topology template not found: %s", _TOPOLOGY_TEMPLATE)
        return

    html = _TOPOLOGY_TEMPLATE.read_text(encoding="utf-8")

    if _AUTOLOAD_MARKER not in html:
        logging.warning("Topology template format changed — could not inject data.")
        return

    injected = (
        f"const LIVE_DATA = {json.dumps(results)};\n"
        f'window.addEventListener("load", () => render(LIVE_DATA));'
    )
    html = html.replace(_AUTOLOAD_MARKER, injected)

    viz_path = json_path.with_suffix(".html").resolve()
    viz_path.write_text(html, encoding="utf-8")

    webbrowser.open(viz_path.as_uri())
    print(f"[+] Visualizer: {viz_path.resolve()}")


# ===========================================================================
# 5. PROBE LOOP
# ===========================================================================

def trace_target(target_ip: str, args: argparse.Namespace) -> dict:
    """Send probes for all TTLs, wait for replies, return raw hop_data."""
    for ttl in range(args.first_ttl, args.max_ttl + 1):
        send_series(
            target_ip,
            ttl,
            args.queries,
            pr.active_probes,
            udp_port=args.udp_port,
            tcp_port=args.tcp_port,
            inter_packet_delay=args.wait,
            packet_size=args.packet_size,
        )
        if target_ip in pr.destination_reached:
            logging.debug("Destination %s reached at TTL %d, stopping.", target_ip, ttl)
            break

    time.sleep(args.timeout)

    hop_data = dict(pr.results.get(target_ip, {}))
    pr.clear_target(target_ip)
    return hop_data


# ===========================================================================
# 5. MAIN
# ===========================================================================

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(stream=sys.stderr, level=log_level, format="%(levelname)s  %(message)s")

    if args.first_ttl > args.max_ttl:
        parser.error(f"--first-ttl ({args.first_ttl}) must be ≤ --max-ttl ({args.max_ttl}).")

    if os.name != "nt" and os.geteuid() != 0:
        logging.warning("Raw sockets require root. Re-run with sudo if probes fail.")

    try:
        targets = parse_target_file(args.target_file)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        logging.error("Input file error: %s", exc)
        return 1

    out_path = Path(args.output_file) if args.output_file else _default_output_path()

    init_sender()
    pr.start_receiver(args.timeout)

    print(f"[+] Starting run — {len(targets)} target(s)  →  {out_path.resolve()}")

    all_results = {}
    exit_code   = 0

    for idx, target_ip in enumerate(targets, start=1):
        print(f"\n[{idx}/{len(targets)}] Tracing {target_ip} …")
        logging.debug("Dispatching probes for target %s", target_ip)

        try:
            hop_data = trace_target(target_ip, args)
        except PermissionError:
            logging.error("Permission denied while probing %s — re-run with sudo.", target_ip)
            exit_code = 1
            continue
        except Exception as exc:
            logging.error("Unexpected error for target %s: %s", target_ip, exc)
            exit_code = 1
            continue

        all_results[target_ip] = build_json_result(target_ip, hop_data)
        print(f"    {len(hop_data)} hop(s) recorded.")

    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(all_results, fh, indent=2)
    except OSError as exc:
        logging.error("Cannot write output file: %s", exc)
        return 1

    print(f"\n[+] Done. Results written to {out_path.resolve()} ({len(targets)} target(s) processed).")

    if args.open:
        launch_visualizer(all_results, out_path)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
