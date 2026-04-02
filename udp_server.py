import datetime
import json
import os
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, DNSRecord, RR

from blocklist import load_blocklist
from cache import DNSCache, extract_ttl
from forwarder import DNSForwarder


BASE_DIR = os.path.dirname(__file__)
HOST = "0.0.0.0"
PORT = 853
BUFFER_SIZE = 4096
MAX_WORKERS = 20
UPSTREAM_TIMEOUT_SEC = 2
DEFAULT_CACHE_TTL = 60

# Round-robin DNS-over-TLS upstream pool used by forwarder.py for load balancing.
UPSTREAM_DNS = [("8.8.8.8", 853), ("1.1.1.1", 853)]

BLOCKLIST_PATH = os.path.join(BASE_DIR, "blocklist.txt")
LOCAL_HOSTS_PATH = os.path.join(BASE_DIR, "local_hosts.json")
LOG_PATH = os.path.join(BASE_DIR, "dns_logs.txt")
TLS_CERT_PATH = os.path.join(BASE_DIR, "server.crt")
TLS_KEY_PATH = os.path.join(BASE_DIR, "server.key")

BLOCK_TTL = 60
LOCAL_DB_TTL = 300

cache = DNSCache()
blocked_domains = load_blocklist(BLOCKLIST_PATH)
forwarder = DNSForwarder(
    upstream_servers=UPSTREAM_DNS,
    timeout_sec=UPSTREAM_TIMEOUT_SEC,
    buffer_size=BUFFER_SIZE,
    verify_tls=False,
    server_hostname=None,
)
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


def make_servfail_response(request):
    reply = request.reply()
    reply.header.rcode = 2
    return reply.pack()


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def send_framed_dns_response(tls_sock, payload):
    tls_sock.sendall(len(payload).to_bytes(2, byteorder="big") + payload)


def log_query(domain, client_addr, result, latency_ms):
    with log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as file_handle:
            file_handle.write(
                f"{datetime.datetime.now()} | {domain} | {client_addr} | {result} | {latency_ms:.2f} ms\n"
            )


def resolve_query(packet, local_hosts):
    """Resolve one DNS query packet and return (response, domain, result_label)."""
    request = parse_dns_query(packet)
    if request is None:
        return None, "<malformed>", "malformed"

    domain = normalize_domain(str(request.q.qname))
    result = "error"

    # 1) Blocklist check.
    if domain in blocked_domains:
        response = make_a_response(request, domain, "0.0.0.0", BLOCK_TTL)
        cache.set(domain, response, BLOCK_TTL)
        result = "blocked"
    else:
        # 2) Cache check.
        cached_response = cache.get(domain)
        if cached_response:
            response = cached_response
            result = "cache"
        else:
            # 3) Local file/DB check.
            if domain in local_hosts:
                response = make_a_response(request, domain, local_hosts[domain], LOCAL_DB_TTL)
                cache.set(domain, response, LOCAL_DB_TTL)
                result = "local-db"
            else:
                # 4) Forward unresolved queries to upstream DNS-over-TLS with round-robin balancing.
                response = forwarder.forward(packet, request.header.id)
                if response:
                    ttl = extract_ttl(response, fallback_ttl=DEFAULT_CACHE_TTL)
                    cache.set(domain, response, ttl)
                    result = "forward"
                else:
                    # If all upstreams fail, return SERVFAIL based on request context.
                    response = make_servfail_response(request)
                    result = "servfail"

    return response, domain, result


def handle_client_connection(raw_client_sock, client_addr, tls_context, local_hosts):
    """Handle one TLS client connection and process DNS queries in a loop."""
    try:
        with tls_context.wrap_socket(raw_client_sock, server_side=True) as tls_sock:
            while True:
                length_prefix = recv_exact(tls_sock, 2)
                if not length_prefix:
                    return

                packet_len = int.from_bytes(length_prefix, byteorder="big")
                if packet_len <= 0 or packet_len > 65535:
                    return

                packet = recv_exact(tls_sock, packet_len)
                if not packet:
                    return

                start_time = time.time()
                response, domain, result = resolve_query(packet, local_hosts)
                if response:
                    send_framed_dns_response(tls_sock, response)

                latency_ms = (time.time() - start_time) * 1000
                print(f"Request from {client_addr} | Domain: {domain} | Path: {result} | {latency_ms:.2f} ms")
                log_query(domain, client_addr, result, latency_ms)
    except (OSError, ssl.SSLError) as exc:
        print(f"Connection error from {client_addr}: {exc}")


def create_server_tls_context(cert_path=TLS_CERT_PATH, key_path=TLS_KEY_PATH):
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(
            f"TLS certificate/key not found. Expected files: {cert_path}, {key_path}"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return context


def run_tls_dns_server(host=HOST, port=PORT):
    """Run a concurrent DNS-over-TLS server with secure upstream forwarding."""
    local_hosts = load_local_hosts(LOCAL_HOSTS_PATH)
    tls_context = create_server_tls_context()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(128)

    print(f"DNS-over-TLS server listening on {host}:{port}")
    print(f"Blocked domains loaded: {len(blocked_domains)}")
    print(f"Local hosts loaded: {len(local_hosts)}")
    print(f"Upstream DNS pool: {UPSTREAM_DNS}")
    print(f"TLS certificate: {TLS_CERT_PATH}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            client_sock, client_addr = server_sock.accept()
            executor.submit(handle_client_connection, client_sock, client_addr, tls_context, local_hosts)


if __name__ == "__main__":
    run_tls_dns_server()