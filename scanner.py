#!/usr/bin/env python3
"""Multithreaded TCP port scanner with optional banner grabbing.

Core scan() returns results for the Flask UI. The CLI still prints them.
"""

from __future__ import annotations

import argparse
import socket
import sys
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

CONNECT_TIMEOUT = 1.0
BANNER_TIMEOUT = 1.0
BANNER_BYTES = 1024
MAX_PORT = 65535

COMMON_SERVICES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}

# Compact stand-in for nmap --top-ports 100
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]

SERVICE_PRESETS: dict[str, list[int]] = {
    "web": [80, 443, 8080],
    "remote": [22, 3389],
    "database": [3306, 5432, 27017],
    "mail": [25, 110, 143],
    "file": [21, 445],
}

ProgressCallback = Callable[[int, int, dict | None], None]


def parse_ports(spec: str) -> list[int]:
    """Turn '1-1000', '80', or '22,80,443-445' into a sorted unique port list."""
    ports: set[int] = set()
    parts = [part.strip() for part in spec.split(",") if part.strip()]
    if not parts:
        raise ValueError("port range is empty")

    for part in parts:
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {part!r}") from exc
            if start > end:
                start, end = end, start
        else:
            try:
                start = end = int(part)
            except ValueError as exc:
                raise ValueError(f"invalid port: {part!r}") from exc

        if start < 1 or end > MAX_PORT:
            raise ValueError(f"ports must be between 1 and {MAX_PORT}: {part!r}")
        ports.update(range(start, end + 1))

    return sorted(ports)


def guess_service(port: int, banner: str = "") -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    lower = banner.lower()
    if "ssh" in lower:
        return "ssh"
    if "http" in lower:
        return "http"
    if "ftp" in lower:
        return "ftp"
    if "smtp" in lower:
        return "smtp"
    return "unknown"


def clean_banner(raw: bytes) -> str:
    text = raw.decode("latin-1", errors="replace")
    return " ".join(text.replace("\r", " ").replace("\n", " ").split())


def http_probe(host: str) -> bytes:
    try:
        host_bytes = host.encode("idna")
    except UnicodeError:
        host_bytes = b"localhost"
    return b"HEAD / HTTP/1.0\r\nHost: " + host_bytes + b"\r\n\r\n"


def read_banner(sock: socket.socket, host: str) -> str:
    sock.settimeout(BANNER_TIMEOUT)
    try:
        data = sock.recv(BANNER_BYTES)
        if data:
            return clean_banner(data)
    except (TimeoutError, socket.timeout, OSError):
        pass

    try:
        sock.sendall(http_probe(host))
        data = sock.recv(BANNER_BYTES)
        if data:
            return clean_banner(data)
    except (TimeoutError, socket.timeout, OSError):
        pass

    return ""


def scan_port(host: str, port: int, identify: bool = True) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        if sock.connect_ex((host, port)) != 0:
            return None
        banner = ""
        if identify:
            try:
                banner = read_banner(sock, host)
            except Exception:  # noqa: BLE001 - still report the open.port
                banner = ""
        return {
            "port": port,
            "state": "open",
            "service": guess_service(port, banner),
            "banner": banner,
        }
    except (TimeoutError, socket.timeout, OSError):
        return None
    finally:
        sock.close()


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve host: {target}") from exc


def scan(
    host: str,
    ports: str | Iterable[int],
    threads: int = 100,
    grab_banner: bool = True,
    progress_callback: ProgressCallback | None = None,
) -> list[dict]:
    """Scan a host. Returns open-port dicts sorted by port number."""
    if isinstance(ports, str):
        port_list = parse_ports(ports)
    else:
        port_list = sorted({int(p) for p in ports})

    if not port_list:
        return []

    ip = resolve_target(host)
    workers = max(1, min(threads, len(port_list)))
    results: list[dict] = []
    completed = 0
    total = len(port_list)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, ip, port, grab_banner): port for port in port_list
        }
        for future in as_completed(futures):
            port = futures[future]
            finding: dict | None = None
            try:
                finding = future.result()
            except Exception as exc:  # noqa: BLE001
                print(f"[!] error on port {port}: {exc}", file=sys.stderr)
            if finding:
                results.append(finding)
            completed += 1
            if progress_callback:
                try:
                    progress_callback(completed, total, finding, port)
                except TypeError:
                    progress_callback(completed, total, finding)

    results.sort(key=lambda item: item["port"])
    return results


def scan_host(host: str, ports: Iterable[int], threads: int) -> list[dict]:
    """Back-compat wrapper used by early CLI experiments."""
    return scan(host, ports, threads=threads, grab_banner=True)


def print_results(target: str, ip: str, results: list[dict], elapsed: float = 0.0) -> None:
    print(f"\n[+] Scan report for {target} ({ip})")
    if not results:
        print("[-] No open ports discovered.")
        return

    print("-" * 75)
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<16}BANNER / VERSION")
    print("-" * 75)
    for item in results:
        banner = item.get("banner") or "-"
        service = item.get("service") or "-"
        port_proto = f"{item['port']}/tcp"
        print(f"{port_proto:<10}{item['state']:<10}{service:<16}{banner}")
    print("-" * 75)
    if elapsed > 0:
        print(f"[+] Discovered {len(results)} open port(s) in {elapsed:.2f} seconds.\n")
    else:
        print(f"[+] Discovered {len(results)} open port(s).\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP port scanner with banner grabbing."
    )
    parser.add_argument("-t", "--target", required=True, help="hostname or IP to scan")
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="port range, e.g. 1-1024 or 22,80,443",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="number of concurrent workers (default: 100)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip banner grabbing / software identification",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be at least 1")

    try:
        ports = parse_ports(args.ports)
        ip = resolve_target(args.target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    import time
    start_time = time.time()
    print(f"[*] Starting TCP reconnaissance on {args.target} ({ip})...")
    print(f"[*] Ports: {args.ports} | Workers: {args.threads} | Banner Grabbing: {not args.no_banner}")
    results = scan(
        args.target,
        ports,
        threads=args.threads,
        grab_banner=not args.no_banner,
    )
    elapsed = time.time() - start_time
    print_results(args.target, ip, results, elapsed=elapsed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
