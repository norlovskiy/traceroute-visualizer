import socket
import time
import threading

import struct

from scapy.all import AsyncSniffer, IP, ICMP, UDP, TCP, IPerror, UDPerror, TCPerror, ICMPerror, Raw, conf

conf.verb = 0

# ---------------- Shared state -----------------
active_probes = {}
probe_lock = threading.Lock()
results = {}
results_lock = threading.Lock()

destination_reached = set()

_timeout_sec = 3.0
_sniffer_ready = threading.Event()

# ---------------- DNS helper ----------------
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip

# ---------------- Scapy packet handler ----------------
def _on_icmp_packet(pkt):
    if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
        return

    recv_time = time.time()
    router_ip = pkt[IP].src
    icmp = pkt[ICMP]

    #print(f"[DBG] pkt  from={router_ip}  icmp_type={icmp.type}  icmp_code={icmp.code}", flush=True)

    if icmp.type in (3, 11):
        # ICMP error — payload is IPerror (subclass of IP); use isinstance not haslayer
        # because haslayer() uses == not isinstance and misses subclasses.
        inner = icmp.payload
        if not isinstance(inner, IP):  # IPerror (real captures) and IP (tests) both match
            #print(f"[DBG] DROP  no inner IP layer, payload type={type(inner).__name__}", flush=True)
            return

        transport = inner.payload
        #print(f"[DBG] inner  proto={inner.proto}  transport_type={type(transport).__name__}", flush=True)

        if isinstance(transport, UDP):    # UDPerror is a subclass of UDP
            key = ("udp", transport.sport)
        elif isinstance(transport, TCP):  # TCPerror is a subclass of TCP
            key = ("tcp", transport.sport)
        elif isinstance(transport, ICMP): # ICMPerror is a subclass of ICMP
            key = ("icmp", transport.seq)
        elif isinstance(transport, Raw):
            # Scapy couldn't reassemble inner transport — parse bytes manually.
            # RFC 792: ICMP error payload contains original IP header + first 8
            # bytes of original datagram. Those 8 bytes are enough for src_port
            # (UDP/TCP bytes 0–1) or ICMP seq (bytes 6–7).
            raw = bytes(transport)
            proto = inner.proto
            #print(f"[DBG] Raw fallback  inner.proto={proto}  raw_hex={raw[:8].hex()}", flush=True)
            if proto == 17 and len(raw) >= 2:
                key = ("udp", struct.unpack("!H", raw[:2])[0])
            elif proto == 6 and len(raw) >= 2:
                key = ("tcp", struct.unpack("!H", raw[:2])[0])
            elif proto == 1 and len(raw) >= 8:
                key = ("icmp", struct.unpack("!H", raw[6:8])[0])
            else:
                #print(f"[DBG] DROP  Raw but proto={proto} len={len(raw)}", flush=True)
                return
        else:
            #print(f"[DBG] DROP  unhandled transport type={type(transport).__name__}", flush=True)
            return

    elif icmp.type == 0:
        # Echo Reply — sequence directly identifies the probe
        key = ("icmp", icmp.seq)
    else:
        #print(f"[DBG] DROP  unhandled icmp_type={icmp.type}", flush=True)
        return

    with probe_lock:
        probe = active_probes.pop(key, None)
        active_keys_snapshot = list(active_probes.keys()) if probe is None else None

    if probe is None:
        #print(f"[DBG] MISS  key={key}  active_probes={active_keys_snapshot}", flush=True)
        return

    #print(f"[DBG] HIT   key={key}  ttl={probe['ttl']}  dst={probe['dst_ip']}", flush=True)

    proto  = key[0]
    rtt_ms = round((recv_time - probe["sent_at"]) * 1000, 2)
    dest   = probe["dst_ip"]
    ttl    = probe["ttl"]

    with results_lock:
        ttl_entry = results.setdefault(dest, {}).setdefault(ttl, {})
        if proto not in ttl_entry:
            # hostname left as None; resolved later in build_hop_entry
            ttl_entry[proto] = {"router_ip": router_ip, "hostname": None, "samples": []}
        ttl_entry[proto]["samples"].append(rtt_ms)

    if icmp.type == 0 and router_ip == dest:
        destination_reached.add(dest)
    elif icmp.type == 3 and icmp.code == 3 and router_ip == dest:
        destination_reached.add(dest)


def _listen():
    try:
        sniffer = AsyncSniffer(
            filter="icmp",
            store=False,
            prn=_on_icmp_packet,
            started_callback=_sniffer_ready.set,
        )
        sniffer.start()
        sniffer.join()
    except PermissionError:
        print("Error: Raw sockets require root/admin privileges.")
        _sniffer_ready.set()
    except Exception as e:
        print(f"Listener error: {e}")
        _sniffer_ready.set()


# ---------------- Timeout reaper ----------------
def reap_timed_out_probes():
    while True:
        time.sleep(0.5)
        now = time.time()
        expired = []

        with probe_lock:
            # list() snapshot prevents RuntimeError if sender adds during iteration
            for key, probe in list(active_probes.items()):
                if now - probe["sent_at"] > _timeout_sec:
                    expired.append((key, probe))
            for key, _ in expired:
                active_probes.pop(key, None)

        # Write results outside probe_lock to avoid nesting locks
        with results_lock:
            for _, probe in expired:
                proto     = probe["protocol"]
                ttl_entry = results.setdefault(probe["dst_ip"], {}).setdefault(probe["ttl"], {})
                if proto not in ttl_entry:
                    ttl_entry[proto] = {"router_ip": "*", "hostname": "*", "samples": []}
                ttl_entry[proto]["samples"].append(None)


# ---------------- Public helpers ----------------
def start_receiver(timeout_sec: float = 3.0):
    """Start the ICMP listener and reaper, blocking until the sniffer socket is open."""
    global _timeout_sec
    _timeout_sec = timeout_sec

    threading.Thread(target=_listen, daemon=True).start()
    threading.Thread(target=reap_timed_out_probes, daemon=True).start()

    # Block until AsyncSniffer fires started_callback (socket open + BPF applied),
    # then a short sleep ensures the recv loop is entered before the first probe.
    _sniffer_ready.wait(timeout=5.0)
    time.sleep(0.1)


def clear_target(dst_ip: str):
    """Remove all stored state for a target IP. Call after processing each target."""
    with probe_lock:
        stale = [k for k, p in active_probes.items() if p.get("dst_ip") == dst_ip]
        for k in stale:
            active_probes.pop(k, None)
    with results_lock:
        results.pop(dst_ip, None)
    destination_reached.discard(dst_ip)
