import socket
from concurrent.futures import ThreadPoolExecutor

from dnslib import DNSRecord, RCODE


HOST = "0.0.0.0"
PORT = 53
BUFFER_SIZE = 4096
MAX_WORKERS = 20


def parse_dns_query(packet):
    """Parse raw UDP bytes into a DNSRecord. Returns None on malformed packets."""
    try:
        return DNSRecord.parse(packet)
    except Exception:
        return None


def build_servfail_response(request):
    """Build a minimal SERVFAIL reply so clients always receive a DNS response."""
    reply = request.reply()
    reply.header.rcode = RCODE.SERVFAIL
    return reply.pack()


def handle_client_packet(server_sock, packet, client_addr):
    """Handle one client packet: parse DNS query and return a basic reply."""
    request = parse_dns_query(packet)
    if request is None:
        print(f"Malformed DNS packet from {client_addr}")
        return

    domain = str(request.q.qname)
    print(f"Request from {client_addr} | Domain: {domain}")

    response = build_servfail_response(request)
    server_sock.sendto(response, client_addr)


def run_udp_dns_server(host=HOST, port=PORT):
    """Run a concurrent UDP DNS server using a thread pool."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((host, port))

    print(f"UDP DNS core server listening on {host}:{port}")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            packet, client_addr = server_sock.recvfrom(BUFFER_SIZE)
            executor.submit(handle_client_packet, server_sock, packet, client_addr)


if __name__ == "__main__":
    run_udp_dns_server()
