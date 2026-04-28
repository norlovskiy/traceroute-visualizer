# traceviz

Multi-protocol traceroute tool with an interactive network topology visualizer.

Sends **UDP**, **TCP SYN**, and **ICMP Echo** probes at every TTL hop for each target, captures ICMP replies with Scapy, and records per-hop RTT and packet-loss statistics. Results are written to JSON and optionally opened in a D3-based topology graph.

---

## Requirements

- Python 3.10+
- [Scapy](https://scapy.net/) 2.5+
- Root / sudo (raw sockets)

```bash
pip install scapy
```

---

## Usage

```
sudo python traceroute_main.py TARGET_FILE [options]
```

`TARGET_FILE` is a `.txt` or `.csv` file with one IP address per line. Lines starting with `#` are ignored.

```
targets.txt
───────────
8.8.8.8
1.1.1.1
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-q N` | 1 | Probe series per hop (each series = UDP + TCP + ICMP) |
| `-f TTL` | 1 | First TTL to probe |
| `-m TTL` | 30 | Max TTL (stops early if destination replies) |
| `-p PORT` | 33434 | UDP destination port |
| `--tcp-port PORT` | 80 | TCP SYN destination port |
| `-s BYTES` | 60 | Probe packet size (min 28) |
| `-w SECS` | 0.05 | Delay between probes within a series |
| `--timeout SECS` | 3.0 | Wait for replies after the last probe |
| `-o FILE` | `traceroute_<ts>.json` | Output JSON path |
| `--open` | off | Open the topology visualizer in the browser when done |
| `-v` | off | Verbose logging to stderr |

### Examples

```bash
# Basic run
sudo python traceroute_main.py targets.txt

# Save to a specific file and open the visualizer
sudo python traceroute_main.py targets.txt -o out.json --open

# 3 probe series per hop, 15-hop limit
sudo python traceroute_main.py targets.txt -q 3 -m 15 -o run.json --open
```

---

## Output

Results are written as JSON:

```json
{
  "8.8.8.8": {
    "5": {
      "udp":  { "hop": 5, "protocol": "udp",  "ip": "194.223.152.17", "hostname": "194.223.152.17", "avg_rtt_ms": 41.0,  "loss_pct": 0.0 },
      "tcp":  { "hop": 5, "protocol": "tcp",  "ip": "194.223.152.17", "hostname": "194.223.152.17", "avg_rtt_ms": 35.26, "loss_pct": 0.0 },
      "icmp": { "hop": 5, "protocol": "icmp", "ip": "194.223.152.17", "hostname": "194.223.152.17", "avg_rtt_ms": 39.27, "loss_pct": 0.0 }
    }
  }
}
```

Silent hops are recorded as `"ip": "*"` with `"loss_pct": 100.0`.

---

## Visualizer

`topology (1).html` is a self-contained D3 force-directed graph. Each node is a router; edges are colour-coded by protocol (UDP = blue, TCP = red, ICMP = green). Link length scales with RTT; dashed lines indicate packet loss.

**Two ways to open it:**

1. Pass `--open` to the CLI — the tool writes a standalone `<output>.html` with results embedded and opens it automatically.
2. Open `topology.html` directly in a browser and use **Load results.json** to load any saved output file.

Click a node to see per-protocol RTT and loss in the sidebar.

---

## Files

| File | Role |
|------|------|
| `traceroute_main.py` | CLI entry point — arg parsing, probe loop, JSON output, visualizer launch |
| `packet_sender.py` | Scapy probe construction and sending (UDP / TCP SYN / ICMP Echo) |
| `packet_receiver.py` | Scapy `AsyncSniffer` listener, probe matching, timeout reaper |
| `topology.html` | D3 topology visualizer |
| `targets.txt` | Example target file |
| `test_receiver.py` | Unit tests for the ICMP packet handler |
