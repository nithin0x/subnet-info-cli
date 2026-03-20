#!/usr/bin/env python3
"""subnet-info CLI."""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from typing import Final, TypedDict


PUBLIC_IP_SERVICES: Final[list[str]] = [
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
]
IPV4_MASKS: Final[list[int]] = [32, 24, 16]
IPV6_MASKS: Final[list[int]] = [128, 64, 48]
COMMON_SAMPLE_PORTS: Final[list[tuple[int, str]]] = [
    (22, "SSH - single IP"),
    (443, "HTTPS - single IP"),
    (80, "HTTP - single IP"),
    (3389, "RDP - single IP"),
    (5432, "PostgreSQL - single IP"),
]


class LocalIPInfo(TypedDict):
    ip: str
    version: int
    is_private: bool
    is_loopback: bool


def fetch(url: str, timeout: int = 5) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "subnet-info-cli/0.1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8").strip()


def get_public_ip() -> str:
    """Try several public IP echo services in order."""
    for service in PUBLIC_IP_SERVICES:
        try:
            candidate = fetch(service)
            return str(ipaddress.ip_address(candidate))
        except (
            urllib.error.URLError,
            TimeoutError,
            ValueError,
        ):
            continue
    raise RuntimeError("Could not determine public IP from any service.")


def get_local_ips() -> list[LocalIPInfo]:
    """Return all local interface IPs with their network info."""
    results: list[LocalIPInfo] = []
    hostname = socket.gethostname()
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return results

    seen: set[str] = set()
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen or ip_str.startswith("fe80"):
            continue
        seen.add(ip_str)
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        results.append(
            {
                "ip": ip_str,
                "version": addr.version,
                "is_private": addr.is_private,
                "is_loopback": addr.is_loopback,
            }
        )
    return results


def cidr_variants(ip_str: str) -> dict[str, str]:
    """Return CIDR blocks for a given IP."""
    ip = ipaddress.ip_address(ip_str)
    masks = IPV4_MASKS if ip.version == 4 else IPV6_MASKS
    return {
        f"/{mask}": str(ipaddress.ip_network(f"{ip_str}/{mask}", strict=False))
        for mask in masks
    }


def aws_sg_rule(cidr: str, port: int | None = None, proto: str = "tcp") -> dict[str, str | int]:
    """Format a dict that mirrors an AWS Security Group inbound rule."""
    rule: dict[str, str | int] = {
        "IpProtocol": proto if port else "-1",
        "CidrIp": cidr,
    }
    if port:
        rule["FromPort"] = port
        rule["ToPort"] = port
    return rule


def main() -> None:
    print("=" * 60)
    print("  subnet-info: Your Public IP, CIDR Ranges, and Firewall Rules Generator")
    print("=" * 60)

    print("\n[1] Public (Egress) IP")
    try:
        pub_ip = get_public_ip()
        print(f"    IP : {pub_ip}")
        variants = cidr_variants(pub_ip)
        print("    CIDR variants:")
        for mask, network in variants.items():
            print(f"      {mask:4s}  ->  {network}")
    except RuntimeError as err:
        pub_ip = None
        print(f"    ERROR: {err}")

    print("\n[2] Local Interface IPs")
    local_ips = get_local_ips()
    if local_ips:
        for entry in local_ips:
            tags = []
            if entry["is_loopback"]:
                tags.append("loopback")
            elif entry["is_private"]:
                tags.append("private")
            else:
                tags.append("public")
            print(
                f"    IPv{entry['version']}  {entry['ip']:<40}  [{', '.join(tags)}]"
            )
    else:
        print("    (none detected)")

    if pub_ip:
        print("\n[3] Sample Rules (JSON)")
        print("    (examples only - add/remove rules based on your requirement)\n")

        narrow_cidr = variants["/32"] if "/32" in variants else variants["/128"]
        broad_cidr = variants["/24"] if "/24" in variants else variants["/64"]

        rules = [{**aws_sg_rule(narrow_cidr, port), "Description": description} for port, description in COMMON_SAMPLE_PORTS]
        rules.append(
            {
                **aws_sg_rule(broad_cidr),
                "Description": f"{broad_cidr} - all traffic (use only if required)",
            }
        )

        print(json.dumps(rules, indent=4))

    print("=" * 60)
    print("  Tip: Use /32 for a single IP, /24 for your whole subnet.")
    print("=" * 60)


if __name__ == "__main__":
    main()
