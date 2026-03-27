import datetime
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, DNSRecord, RR


# CONFIG
# Values can be overridden via environment variables for easy deployment changes.

BASE_DIR = os.path.dirname(__file__)
HOST = os.getenv("DNS_HOST", "0.0.0.0")
PORT = int(os.getenv("DNS_PORT", "53"))

UPSTREAM_DNS = [("8.8.8.8", 53), ("1.1.1.1", 53)]
MAX_WORKERS = int(os.getenv("DNS_WORKERS", "20"))
UPSTREAM_TIMEOUT_SEC = 2
BUFFER_SIZE = 4096


# CACHE + BLOCKLIST
# The server keeps local state for fast responses and policy enforcement.
BLOCKLIST_PATH = os.path.join(BASE_DIR, "blocklist.txt")
LOCAL_HOSTS_PATH = os.path.join(BASE_DIR, "local_hosts.json")
LOG_PATH = os.path.join(BASE_DIR, "dns_logs.txt")

DEFAULT_CACHE_TTL = 60  # fallback seconds


def make_a_response(request, domain, ip, ttl=60):
    """Build a minimal A-record response for blocked/local domains."""
    reply = request.reply()
    reply.add_answer(RR(domain, rdata=A(ip), ttl=ttl))
    return reply.pack()


def send_response(sock, response, addr):
    """Serialize socket sends to keep multi-thread writes predictable."""
    with send_lock:
        sock.sendto(response, addr)


def log_query(domain, addr, latency_ms, result):
    """Append one log line per handled query for audit/debugging."""
    with log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.datetime.now()} | {domain} | {addr} | {result} | {latency_ms:.2f} ms\n"
            )


def handle_request(data, addr, server_sock):
    """Process one DNS request using: blocklist -> cache -> local -> upstream."""
    start_time = time.time()

    try:
        request = DNSRecord.parse(data)
    except Exception:
        print(f"Malformed DNS request from {addr}")
        return

    domain = str(request.q.qname).lower()

    print(f"\nRequest from {addr}")
    print(f"Domain: {domain}")

    result = "error"

    # 1) BLOCKLIST CHECK: blocked names are answered with 0.0.0.0.
    if domain in blocked_domains:
        print("Blocked domain")
        response = make_a_response(request, domain, "0.0.0.0", ttl=60)
        send_response(server_sock, response, addr)
        result = "blocked"
    else:
        # 2) CACHE CHECK: fastest path for repeat queries.
        cached_response = cache.get(domain)
        if cached_response:
            print("Cache HIT")
            send_response(server_sock, cached_response, addr)
            result = "cache"
        else:
            print("Cache MISS")

            # 3) LOCAL DATABASE CHECK: static domain mappings.
            if domain in local_hosts:
                ip = local_hosts[domain]
                print(f"Local DB HIT -> {ip}")
                response = make_a_response(request, domain, ip, ttl=300)
                cache.set(domain, response, 300)
                send_response(server_sock, response, addr)
                result = "local"
            else:
                # 4) FORWARDING: delegate to upstream resolver pool.
                response = forwarder.forward(data, request.header.id)
                if response:
                    # 5) CACHE STORE: use upstream TTL for better expiry behavior.
                    ttl = extract_ttl(response, fallback_ttl=DEFAULT_CACHE_TTL)
                    cache.set(domain, response, ttl)
                    send_response(server_sock, response, addr)
                    result = "forward"
                else:
                    print("Failed to resolve")

    latency = (time.time() - start_time) * 1000
    print(f"Response path: {result} | {latency:.2f} ms")
    log_query(domain, addr, latency, result)


class DNSCache:
    """Thread-safe DNS response cache with per-record expiry timestamps."""

    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get(self, domain):
        """Return a cached response if valid; remove and miss on expiry."""
        now = time.time()
        with self._lock:
            item = self._cache.get(domain)
            if not item:
                return None

            response, expiry = item
            if now < expiry:
                return response

            del self._cache[domain]
            return None

    def set(self, domain, response, ttl):
        """Store a packed DNS response using ttl seconds from now."""
        ttl = max(1, int(ttl))
        with self._lock:
            self._cache[domain] = (response, time.time() + ttl)


def extract_ttl(response_data, fallback_ttl=60):
    """Extract a positive TTL from DNS answers, or return the fallback."""
    try:
        parsed = DNSRecord.parse(response_data)
        ttls = [rr.ttl for rr in parsed.rr if rr.ttl > 0]
        if ttls:
            return min(ttls)
    except Exception:
        pass

    return fallback_ttl


class DNSForwarder:
    """Round-robin upstream DNS forwarder with response validation."""

    def __init__(self, upstream_servers, timeout_sec=2, buffer_size=4096):
        if not upstream_servers:
            raise ValueError("upstream_servers must not be empty")

        self._upstream_servers = list(upstream_servers)
        self._timeout_sec = timeout_sec
        self._buffer_size = buffer_size
        self._index = 0
        self._lock = threading.Lock()

    def _next_server(self):
        with self._lock:
            server = self._upstream_servers[self._index]
            self._index = (self._index + 1) % len(self._upstream_servers)
            return server

    def forward(self, query_data, request_id):
        """Try each upstream server until one valid DNS reply is returned."""
        for _ in range(len(self._upstream_servers)):
            server = self._next_server()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
                    upstream_sock.settimeout(self._timeout_sec)
                    upstream_sock.sendto(query_data, server)
                    response, _ = upstream_sock.recvfrom(self._buffer_size)

                try:
                    upstream_record = DNSRecord.parse(response)
                except Exception:
                    continue

                if upstream_record.header.id != request_id:
                    continue

                return response
            except (socket.timeout, OSError):
                continue

        return None


# MAIN SERVER
# The receive loop stays lightweight and dispatches work to the thread pool.

cache = DNSCache()
blocked_domains = {}  # Placeholder, assuming loaded elsewhere
local_hosts = {}  # Placeholder, assuming loaded elsewhere
forwarder = DNSForwarder(
    upstream_servers=UPSTREAM_DNS,
    timeout_sec=UPSTREAM_TIMEOUT_SEC,
    buffer_size=BUFFER_SIZE,
)
log_lock = threading.Lock()
send_lock = threading.Lock()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((HOST, PORT))

print(f"DNS Server running on {HOST}:{PORT}")
print(f"Blocked domains loaded: {len(blocked_domains)}")
print(f"Local hosts loaded: {len(local_hosts)}")

with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            # Each packet is handled independently to support concurrent clients.
            executor.submit(handle_request, data, addr, sock)
        except KeyboardInterrupt:
            print("Shutting down DNS server")
            break
        except OSError as exc:
            print(f"Server socket error: {exc}")