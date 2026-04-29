import os
import platform
import re
import subprocess
import time
import random
import itertools

from scapy.all import IP, ICMP, UDP, TCP, Raw, send, conf

_ICMP_ID = os.getpid() & 0xFFFF
_seq_counter = itertools.count(start=1)


def _prime_gateway_arp():
    # On Windows/macOS, Scapy sends at L2 via Npcap/BPF and must resolve the
    # gateway MAC itself. Without a warm ARP cache it warns and falls back to
    # broadcast, which routers silently drop. Linux uses kernel raw sockets so
    # the kernel handles ARP and this step is unnecessary.
    from scapy.all import getmacbyip
    try:
        iface, _, gw = conf.route.route("0.0.0.0")
        conf.iface = iface
        if not gw or gw == "0.0.0.0":
            return
        mac = getmacbyip(gw)
        if mac:
            return  # Scapy's ARP succeeded; cache is warm
        # getmacbyip() can fail on Windows/macOS when Npcap/BPF doesn't
        # capture the ARP reply in time. Fall back to the OS ARP table,
        # which is always populated for the default gateway once the
        # machine has an active internet connection.
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["arp", "-a", gw], text=True, timeout=3,
                stderr=subprocess.DEVNULL,
            )
        else:  # macOS
            out = subprocess.check_output(
                ["arp", "-n", gw], text=True, timeout=3,
                stderr=subprocess.DEVNULL,
            )
        m = re.search(r"([\da-fA-F]{1,2}[:\-]){5}[\da-fA-F]{1,2}", out)
        if m:
            conf.netcache.arp_cache[gw] = m.group(0).replace("-", ":").lower()
    except Exception:
        pass


def init_sender():
    conf.verb = 0
    if platform.system() != "Linux":
        _prime_gateway_arp()


def craft_icmp_probe(dst_ip: str, ttl: int, seq: int, size: int = 60):
    payload_len = max(0, size - 20 - 8)
    return IP(dst=dst_ip, ttl=ttl) / ICMP(type=8, id=_ICMP_ID, seq=seq) / Raw(b"X" * payload_len)


def craft_udp_probe(dst_ip: str, ttl: int, dst_port: int, src_port: int, size: int = 60):
    payload_len = max(0, size - 20 - 8)
    return IP(dst=dst_ip, ttl=ttl) / UDP(sport=src_port, dport=dst_port) / Raw(b"X" * payload_len)


def craft_tcp_probe(dst_ip: str, ttl: int, dst_port: int, src_port: int):
    return IP(dst=dst_ip, ttl=ttl) / TCP(sport=src_port, dport=dst_port, flags="S")


def send_series(
    destination_ip: str,
    current_ttl: int,
    num_series: int,
    active_probes: dict,
    *,
    udp_port: int = 33434,
    tcp_port: int = 80,
    inter_packet_delay: float = 0.05,
    packet_size: int = 60,
):
    for _ in range(num_series):
        # UDP
        src_port_udp = random.randint(49152, 65535)
        pkt = craft_udp_probe(destination_ip, current_ttl, udp_port, src_port_udp, packet_size)
        active_probes[("udp", src_port_udp)] = {
            "protocol": "udp",
            "sent_at": time.time(),
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "dst_port": udp_port,
            "src_port": src_port_udp,
        }
        send(pkt)
        time.sleep(inter_packet_delay)

        # TCP
        src_port_tcp = random.randint(49152, 65535)
        pkt = craft_tcp_probe(destination_ip, current_ttl, tcp_port, src_port_tcp)
        active_probes[("tcp", src_port_tcp)] = {
            "protocol": "tcp",
            "sent_at": time.time(),
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "dst_port": tcp_port,
            "src_port": src_port_tcp,
        }
        send(pkt)
        time.sleep(inter_packet_delay)

        # ICMP
        seq = next(_seq_counter)
        pkt = craft_icmp_probe(destination_ip, current_ttl, seq, packet_size)
        active_probes[("icmp", seq)] = {
            "protocol": "icmp",
            "sent_at": time.time(),
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "icmp_id": _ICMP_ID,
            "seq": seq,
        }
        send(pkt)
        time.sleep(inter_packet_delay)


if __name__ == "__main__":
    import pprint

    TARGET_IP          = "1.1.1.1"
    NUM_SERIES         = 1      # -q
    INITIAL_TTL        = 1      # -f
    MAX_TTL            = 30     # -m
    UDP_PORT           = 33434  # -p
    TCP_PORT           = 80
    PACKET_SIZE        = 60     # -s
    INTER_PACKET_DELAY = 0.05   # -w

    init_sender()
    active_probes = {}
    for ttl in range(INITIAL_TTL, MAX_TTL + 1):
        send_series(
            TARGET_IP,
            ttl,
            NUM_SERIES,
            active_probes,
            udp_port=UDP_PORT,
            tcp_port=TCP_PORT,
            inter_packet_delay=INTER_PACKET_DELAY,
            packet_size=PACKET_SIZE,
        )

    print(f"\nActive Probe Table ({len(active_probes)} entries):")
    pprint.pprint(active_probes)
