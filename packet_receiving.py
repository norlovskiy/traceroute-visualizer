import socket
import time
import threading

from scapy.all import AsyncSniffer, IP, ICMP, UDP, TCP, IPerror, UDPerror, TCPerror, ICMPerror, conf

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

    if icmp.type in (3, 11):
        # ICMP error — payload is IPerror (subclass of IP); use isinstance not haslayer
        # because haslayer() uses == not isinstance and misses subclasses.
        inner = icmp.payload
        if not isinstance(inner, IP):  # IPerror (real captures) and IP (tests) both match
            return

        transport = inner.payload
        if isinstance(transport, UDP):    # UDPerror is a subclass of UDP
            key = ("udp", transport.sport)
        elif isinstance(transport, TCP):  # TCPerror is a subclass of TCP
            key = ("tcp", transport.sport)
        elif isinstance(transport, ICMP): # ICMPerror is a subclass of ICMP
            key = ("icmp", transport.seq)
        else:
            return

    elif icmp.type == 0:
        # Echo Reply — sequence directly identifies the probe
        key = ("icmp", icmp.seq)
    else:
        return

    with probe_lock:
        probe = active_probes.pop(key, None)

    if probe is None:
        return

    proto   = key[0]
    rtt_ms  = round((recv_time - probe["sent_at"]) * 1000, 2)
    hostname = resolve_hostname(router_ip)
    dest    = probe["dst_ip"]
    ttl     = probe["ttl"]

    with results_lock:
        ttl_entry = results.setdefault(dest, {}).setdefault(ttl, {})
        if proto not in ttl_entry:
            ttl_entry[proto] = {"router_ip": router_ip, "hostname": hostname, "samples": []}
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

    # Block until AsyncSniffer fires started_callback, guaranteeing the socket
    # is open before the first probe is sent.
    _sniffer_ready.wait(timeout=5.0)


def clear_target(dst_ip: str):
    """Remove all stored state for a target IP. Call after processing each target."""
    with results_lock:
        results.pop(dst_ip, None)
    destination_reached.discard(dst_ip)
