import socket
import time
import struct
import threading

# ---------------- Shared state -----------------
active_probes = {} # for B
probe_lock = threading.Lock()
results = {} # for A
results_lock = threading.Lock()

destination_reached = set()

# ---------------- DNS helper ----------------
def resolve_hostname(ip): #trys to get domain name via reverse dns lookup
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ip

# ---------------- Core parser ------------------------
def parse_icmp_response(raw_data, recv_time, router_ip):
    try:
        if len(raw_data) < 28:
            return

        # Outer IP header
        outer_ihl = (raw_data[0] & 0x0F) * 4
        icmp_start = outer_ihl

        if len(raw_data) < icmp_start + 8:
            return

        # ICMP Header
        icmp_type, icmp_code = struct.unpack("!BB", raw_data[icmp_start:icmp_start + 2])

        # Type 11 = Time Exceeded
        # Type 3  = Destination Unreachable
        # Type 0  = Echo Reply

        inner_ip_start = icmp_start + 8

        if icmp_type == 0:
            # Echo Reply: identifier/seq are in the outer ICMP header itself (no inner IP)
            # Echo Reply is a direct ICMP response
            inner_proto = socket.IPPROTO_ICMP
            inner_transport = icmp_start
        else:
            # ICMP error messages quote the original packet
            if len(raw_data) < inner_ip_start + 20:
                return

            inner_ihl = (raw_data[inner_ip_start] & 0x0F) * 4

            if len(raw_data) < inner_ip_start + inner_ihl:
                return

            inner_proto = raw_data[inner_ip_start + 9]
            inner_transport = inner_ip_start + inner_ihl

        identifier = None
        #proto_name = None

        if inner_proto == socket.IPPROTO_UDP:
            proto_name = "udp"
            if len(raw_data) < inner_transport + 2:
                return
            identifier = struct.unpack("!H", raw_data[inner_transport:inner_transport + 2])[0]

        elif inner_proto == socket.IPPROTO_TCP:
            proto_name = "tcp"
            if len(raw_data) < inner_transport + 2:
                return
            identifier = struct.unpack("!H", raw_data[inner_transport:inner_transport + 2])[0]

        elif inner_proto == socket.IPPROTO_ICMP:
            proto_name = "icmp"
            if len(raw_data) < inner_transport + 8:
                return

            icmp_identifier = struct.unpack("!H", raw_data[inner_transport + 4:inner_transport + 6])[0]
            icmp_sequence   = struct.unpack("!H", raw_data[inner_transport + 6:inner_transport + 8])[0]

        else:
            return[]

        # ---------------- Probe matching ----------------
        if proto_name == "icmp":
            key = ("icmp", icmp_sequence)
        else:
            key = (proto_name, identifier)

        with probe_lock:  # used for getting and releasing locks
            probe = active_probes.pop(key, None)

        if probe is None:
            return

        rtt_ms  = (recv_time - probe["sent_at"]) * 1000
        hostname = resolve_hostname(router_ip)
        ttl = probe["ttl"]
        dest = probe["dst_ip"]

        # ---------------- Store result ----------------
        with results_lock:
            results.setdefault(dest, {}).setdefault(ttl, {})[proto_name] = {
                "router_ip": router_ip,
                "hostname":  hostname,
                "rtt_ms":    round(rtt_ms, 2),
            }

        # ---------------- Stop condition ----------------
        if proto_name == "icmp" and icmp_type == 0 and router_ip == dest:
            destination_reached.add(dest)

        elif proto_name == "icmp" and icmp_type == 3 and icmp_code == 3 and router_ip == dest:
            destination_reached.add(dest)

        # TCP final destination usually responds with TCP SYN-ACK or RST,
        # not ICMP, so we do not mark TCP complete here.

    except Exception as e:
        print(f"Parser error: {e}")

# ---------------- Timeout reaper ----------------
def reap_timed_out_probes(timeout_sec=3):
    while True:
        now = time.time()
        expired_keys = []

        with probe_lock:
            for key, probe in active_probes.items():
                if now - probe["sent_at"] > timeout_sec:
                    expired_keys.append(key)

            for key in expired_keys:
                probe = active_probes.pop(key)
                with results_lock:
                    results.setdefault(probe["dst_ip"], {}) \
                           .setdefault(probe["ttl"], {})[probe["protocol"]] = {
                        "router_ip": "*",
                        "hostname":  "*",
                        "rtt_ms":    None,
                    }

        time.sleep(0.5)

# ---------------- Listener ----------------
def create_listening_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Error: Raw sockets require root/admin privileges.")
        return

    reaper = threading.Thread(target=reap_timed_out_probes, daemon=True)
    reaper.start()

    print("Receiver listening (ICMP)...")
    while True:
        try:
            raw_packet, addr = s.recvfrom(2048)
            recv_time = time.time()
            parse_icmp_response(raw_packet, recv_time, addr[0])
        except Exception as e:
            print(f"Socket error: {e}")



# active_probes[("icmp", seq)] = {
#             "protocol": "icmp",
#             "sent_at": t,
#             "ttl": current_ttl,
#             "dst_ip": destination_ip,
#             "icmp_id": _ICMP_ID,
#             "seq": seq,
# }
