import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from dnslib import DNSRecord


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

    def _query_upstream(self, query_data, server):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.settimeout(self._timeout_sec)
            upstream_sock.sendto(query_data, server)
            response, _ = upstream_sock.recvfrom(self._buffer_size)
            return response

    def forward(self, query_data, request_id):
        """Query all upstreams in parallel and return the first valid DNS reply."""
        ordered_servers = [self._next_server() for _ in range(len(self._upstream_servers))]

        with ThreadPoolExecutor(max_workers=len(ordered_servers)) as executor:
            future_to_server = {
                executor.submit(self._query_upstream, query_data, server): server
                for server in ordered_servers
            }

            for future in as_completed(future_to_server, timeout=self._timeout_sec):
                try:
                    response = future.result()
                except (socket.timeout, OSError):
                    continue

                try:
                    upstream_record = DNSRecord.parse(response)
                except Exception:
                    continue

                if upstream_record.header.id == request_id:
                    return response

        return None
