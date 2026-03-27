# Enhanced Custom DNS Server

## Project Structure

- server.py: main controller and request handling flow
- forwarder.py: upstream DNS forwarding (round-robin + validation)
- cache.py: thread-safe DNS cache and TTL extraction
- blocklist.py: blocklist normalization and loading
- blocklist.txt: blocked domains list (one per line)
- local_hosts.json: local static DNS records
- dns_logs.txt: query logs
- requirements.txt: Python dependencies

## Request Flow

1. Receive DNS query over UDP.
2. Check blocklist and return 0.0.0.0 for blocked domains.
3. Check cache for a valid response.
4. Check local hosts mapping.
5. Forward unresolved query to upstream DNS.
6. Cache response with TTL.
7. Log result and latency.

## Setup

1. Install dependencies:
   pip install -r requirements.txt
2. Optional environment variables:
   - DNS_HOST (default: 0.0.0.0)
   - DNS_PORT (default: 53)
   - DNS_WORKERS (default: 20)
3. Run server:
   python server.py

## Notes

- Port 53 may require administrator privileges.
- Add domains in blocklist.txt (one domain per line).
- Add local mappings in local_hosts.json using {"domain": "ip"} format.
