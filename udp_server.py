import datetime
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, DNSRecord, RR

from blocklist import load_blocklist
from cache import DNSCache, extract_ttl
from forwarder import DNSForwarder


BASE_DIR = os.path.dirname(__file__)
HOST = "0.0.0.0"
PORT = 53
BUFFER_SIZE = 4096
MAX_WORKERS = 20
UPSTREAM_TIMEOUT_SEC = 2
DEFAULT_CACHE_TTL = 60

# Round-robin upstream pool used by forwarder.py for load balancing.
UPSTREAM_DNS = [("8.8.8.8", 53), ("1.1.1.1", 53)]

BLOCKLIST_PATH = os.path.join(BASE_DIR, "blocklist.txt")
LOCAL_HOSTS_PATH = os.path.join(BASE_DIR, "local_hosts.json")
LOG_PATH = os.path.join(BASE_DIR, "dns_logs.txt")

BLOCK_TTL = 60
LOCAL_DB_TTL = 300

cache = DNSCache()
blocked_domains = load_blocklist(BLOCKLIST_PATH)
forwarder = DNSForwarder(
    upstream_servers=UPSTREAM_DNS,
    timeout_sec=UPSTREAM_TIMEOUT_SEC,
    buffer_size=BUFFER_SIZE,
)
send_lock = threading.Lock()
log_lock = threading.Lock()


def normalize_domain(domain):
    cleaned = domain.strip().lower()
    if cleaned and not cleaned.endswith("."):
        cleaned += "."
    return cleaned


def load_local_hosts(path):
    """Load static local DNS mappings from local_hosts.json."""
    if not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as file_handle:
        raw = json.load(file_handle)

    normalized = {}
    for domain, ip in raw.items():
        normalized[normalize_domain(domain)] = ip

    return normalized


def parse_dns_query(packet):
    """Parse raw UDP bytes into a DNSRecord. Returns None on malformed packets."""
    try:
        return DNSRecord.parse(packet)
    except Exception:
        return None


def make_a_response(request, domain, ip, ttl):
    reply = request.reply()
    reply.add_answer(RR(domain, rdata=A(ip), ttl=ttl))
    return reply.pack()


def send_response(server_sock, packet, client_addr):
    with send_lock:
        server_sock.sendto(packet, client_addr)


def log_query(domain, client_addr, result, latency_ms):
    with log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as file_handle:
            file_handle.write(
                f"{datetime.datetime.now()} | {domain} | {client_addr} | {result} | {latency_ms:.2f} ms\n"
            )


def handle_client_packet(server_sock, packet, client_addr, local_hosts):
    """Handle one client packet with blocklist, cache, local DB, forwarding, and logging."""
    start_time = time.time()

    request = parse_dns_query(packet)
    if request is None:
        print(f"Malformed DNS packet from {client_addr}")
        return

    domain = normalize_domain(str(request.q.qname))
    result = "error"

    # 1) Blocklist check.
    if domain in blocked_domains:
        response = make_a_response(request, domain, "0.0.0.0", BLOCK_TTL)
        cache.set(domain, response, BLOCK_TTL)
        send_response(server_sock, response, client_addr)
        result = "blocked"
    else:
        # 2) Cache check.
        cached_response = cache.get(domain)
        if cached_response:
            send_response(server_sock, cached_response, client_addr)
            result = "cache"
        else:
            # 3) Local file/DB check.
            if domain in local_hosts:
                response = make_a_response(request, domain, local_hosts[domain], LOCAL_DB_TTL)
                cache.set(domain, response, LOCAL_DB_TTL)
                send_response(server_sock, response, client_addr)
                result = "local-db"
            else:
                # 4) Forward unresolved queries to upstream DNS with round-robin balancing.
                response = forwarder.forward(packet, request.header.id)
                if response:
                    ttl = extract_ttl(response, fallback_ttl=DEFAULT_CACHE_TTL)
                    cache.set(domain, response, ttl)
                    send_response(server_sock, response, client_addr)
                    result = "forward"
                else:
                    # If all upstreams fail, return SERVFAIL based on request context.
                    reply = request.reply()
                    reply.header.rcode = 2
                    response = reply.pack()
                    send_response(server_sock, response, client_addr)
                    result = "servfail"

    latency_ms = (time.time() - start_time) * 1000
    print(f"Request from {client_addr} | Domain: {domain} | Path: {result} | {latency_ms:.2f} ms")
    log_query(domain, client_addr, result, latency_ms)


def run_udp_dns_server(host=HOST, port=PORT):
    """Run a concurrent UDP DNS server with forwarding and load balancing enabled."""
    local_hosts = load_local_hosts(LOCAL_HOSTS_PATH)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))

    print(f"UDP DNS forwarding server listening on {host}:{port}")
    print(f"Blocked domains loaded: {len(blocked_domains)}")
    print(f"Local hosts loaded: {len(local_hosts)}")
    print(f"Upstream DNS pool: {UPSTREAM_DNS}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            packet, client_addr = server_sock.recvfrom(BUFFER_SIZE)
            executor.submit(handle_client_packet, server_sock, packet, client_addr, local_hosts)


if __name__ == "__main__":
    run_udp_dns_server()
