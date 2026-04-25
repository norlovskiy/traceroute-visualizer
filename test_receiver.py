import socket
import struct
import time

from packet_receiving import parse_icmp_response, active_probes, results, probe_lock

# Pre-load a fake probe that we expect to match
with probe_lock:
    active_probes[("udp", 50001)] = {
        "protocol": "udp",
        "sent_at": time.time() - 0.05,
        "ttl": 3,
        "dst_ip": "1.1.1.1",
    }

# Build fake ICMP Time Exceeded packet
outer_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 56, 0, 0, 64, 1, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.1.1"))
icmp_hdr  = struct.pack("!BBHHH", 11, 0, 0, 0, 0)
inner_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 3, 17, 0,
                         socket.inet_aton("192.168.1.1"), socket.inet_aton("1.1.1.1"))
inner_udp = struct.pack("!HHH", 50001, 33434, 8)

fake_packet = outer_ip + icmp_hdr + inner_ip + inner_udp

parse_icmp_response(fake_packet, time.time(), "10.0.0.1")

#-------------TCP test---------------
with probe_lock:
    active_probes[("tcp", 50002)] = {
        "protocol":  "tcp",
        "sent_at":   time.time() - 0.05,
        "ttl":       3,
        "dst_ip":    "1.1.1.1",
    }

outer_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 56, 0, 0, 64, 1, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.1.1"))
icmp_hdr  = struct.pack("!BBHHH", 11, 0, 0, 0, 0)
inner_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 3, 6, 0,  # 6 = TCP
                         socket.inet_aton("192.168.1.1"), socket.inet_aton("1.1.1.1"))
inner_tcp = struct.pack("!HH", 50002, 33434)  # src_port=50002

fake_packet = outer_ip + icmp_hdr + inner_ip + inner_tcp
parse_icmp_response(fake_packet, time.time(), "10.0.0.1")

#------------ICMP test---------------
with probe_lock:
    active_probes[("icmp", 1)] = {
        "protocol":  "icmp",
        "sent_at":   time.time() - 0.05,
        "ttl":       3,
        "dst_ip":    "1.1.1.1",
    }

outer_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 56, 0, 0, 64, 1, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("192.168.1.1"))
icmp_hdr  = struct.pack("!BBHHH", 11, 0, 0, 0, 0)
inner_ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 3, 1, 0,  # 1 = ICMP
                         socket.inet_aton("192.168.1.1"), socket.inet_aton("1.1.1.1"))
inner_icmp = struct.pack("!BBHHH", 8, 0, 0, 1234, 1)  # type=8, id=1234, seq=1

fake_packet = outer_ip + icmp_hdr + inner_ip + inner_icmp
parse_icmp_response(fake_packet, time.time(), "10.0.0.1")


print(results)
