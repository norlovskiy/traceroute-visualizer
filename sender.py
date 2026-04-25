import os
import time
import random
import itertools

from scapy.all import IP, ICMP, UDP, TCP, Raw, send, conf

_ICMP_ID = os.getpid() & 0xFFFF
_seq_counter = itertools.count(start=1)


def init_sender():
    conf.verb = 0


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
    dst_port: int = 33434,
    inter_packet_delay: float = 0.05,
    packet_size: int = 60,
):
    for _ in range(num_series):
        # UDP
        src_port_udp = random.randint(49152, 65535)
        pkt = craft_udp_probe(destination_ip, current_ttl, dst_port, src_port_udp, packet_size)
        t = time.time()
        send(pkt)
        active_probes[("udp", src_port_udp)] = {
            "protocol": "udp",
            "sent_at": t,
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "dst_port": dst_port,
            "src_port": src_port_udp,
        }
        time.sleep(inter_packet_delay)

        # TCP
        src_port_tcp = random.randint(49152, 65535)
        pkt = craft_tcp_probe(destination_ip, current_ttl, dst_port, src_port_tcp)
        t = time.time()
        send(pkt)
        active_probes[("tcp", src_port_tcp)] = {
            "protocol": "tcp",
            "sent_at": t,
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "dst_port": dst_port,
            "src_port": src_port_tcp,
        }
        time.sleep(inter_packet_delay)

        # ICMP
        seq = next(_seq_counter)
        pkt = craft_icmp_probe(destination_ip, current_ttl, seq, packet_size)
        t = time.time()
        send(pkt)
        active_probes[("icmp", seq)] = {
            "protocol": "icmp",
            "sent_at": t,
            "ttl": current_ttl,
            "dst_ip": destination_ip,
            "icmp_id": _ICMP_ID,
            "seq": seq,
        }
        time.sleep(inter_packet_delay)


if __name__ == "__main__":
    import pprint

    TARGET_IP = "1.1.1.1"
    TTL = 5
    NUM_SERIES = 3
    DST_PORT = 33434
    INTER_PACKET_DELAY = 0.05
    PACKET_SIZE = 60

    init_sender()
    active_probes = {}
    send_series(
        TARGET_IP,
        TTL,
        NUM_SERIES,
        active_probes,
        dst_port=DST_PORT,
        inter_packet_delay=INTER_PACKET_DELAY,
        packet_size=PACKET_SIZE,
    )

    print(f"\nActive Probe Table ({len(active_probes)} entries):")
    pprint.pprint(active_probes)
