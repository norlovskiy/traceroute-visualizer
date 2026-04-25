import time

from scapy.all import IP, ICMP, UDP, TCP, Raw

from packet_receiving import _on_icmp_packet, active_probes, results, probe_lock

# ------------- UDP Time Exceeded -------------
with probe_lock:
    active_probes[("udp", 50001)] = {
        "protocol": "udp",
        "sent_at":  time.time() - 0.05,
        "ttl":      3,
        "dst_ip":   "1.1.1.1",
    }

pkt = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / ICMP(type=11, code=0)
    / IP(src="192.168.1.1", dst="1.1.1.1", proto=17)
    / UDP(sport=50001, dport=33434)
    / Raw(b"\x00" * 4)
)
_on_icmp_packet(pkt)

# ------------- TCP Time Exceeded -------------
with probe_lock:
    active_probes[("tcp", 50002)] = {
        "protocol": "tcp",
        "sent_at":  time.time() - 0.05,
        "ttl":      3,
        "dst_ip":   "1.1.1.1",
    }

pkt = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / ICMP(type=11, code=0)
    / IP(src="192.168.1.1", dst="1.1.1.1", proto=6)
    / TCP(sport=50002, dport=33434)
)
_on_icmp_packet(pkt)

# ------------- ICMP Time Exceeded -------------
with probe_lock:
    active_probes[("icmp", 1)] = {
        "protocol": "icmp",
        "sent_at":  time.time() - 0.05,
        "ttl":      3,
        "dst_ip":   "1.1.1.1",
    }

pkt = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / ICMP(type=11, code=0)
    / IP(src="192.168.1.1", dst="1.1.1.1", proto=1)
    / ICMP(type=8, id=1234, seq=1)
)
_on_icmp_packet(pkt)

print(results)
