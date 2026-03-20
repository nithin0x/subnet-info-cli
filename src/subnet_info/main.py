#!/usr/bin/env python3
"""
AWS Firewall IP Subnet Inspector
Shows your public IP, CIDR ranges, and generates ready-to-use
AWS Security Group / Network Firewall ingress rules.
"""

import ipaddress
import json
import socket
import urllib.request


def fetch(url: str, timeout: int = 5) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode().strip()


def get_public_ip() -> str:
    """Try several public IP echo services in order."""
    services = [
        "https://checkip.amazonaws.com",
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for service in services:
        try:
            ip = fetch(service)
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    raise RuntimeError("Could not determine public IP from any service.")


def get_local_ips() -> list[dict]:
    """Return all local interface IPs with their network info."""
    results = []
    hostname = socket.gethostname()
    try:
        infos = socket.getaddrinfo(hostname, None)
        seen = set()
        for info in infos:
            ip_str = info[4][0]
            if ip_str in seen or ip_str.startswith("fe80"):
                continue
            seen.add(ip_str)
            try:
                addr = ipaddress.ip_address(ip_str)
                results.append(
                    {
                        "ip": ip_str,
                        "version": addr.version,
                        "is_private": addr.is_private,
                        "is_loopback": addr.is_loopback,
                    }
                )
            except ValueError:
                pass
    except Exception:
        pass
    return results


def cidr_variants(ip_str: str) -> dict:
    """Return CIDR blocks for a given IP."""
    ip = ipaddress.ip_address(ip_str)
    masks = [32, 24, 16] if ip.version == 4 else [128, 64, 48]
    return {
        f"/{mask}": str(ipaddress.ip_network(f"{ip_str}/{mask}", strict=False))
        for mask in masks
    }


def aws_sg_rule(cidr: str, port: int | None = None, proto: str = "tcp") -> dict:
    """Format a dict that mirrors an AWS Security Group inbound rule."""
    rule: dict = {
        "IpProtocol": proto if port else "-1",
        "CidrIp": cidr,
    }
    if port:
        rule["FromPort"] = port
        rule["ToPort"] = port
    return rule


def main() -> None:
    print("=" * 60)
    print("  AWS Firewall IP Subnet Inspector")
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
        print("\n[3] Sample AWS Security Group Rules (JSON)")
        print("    (copy into your aws cli / CloudFormation / Terraform)\n")

        common_ports = [22, 443, 80, 3389, 5432]
        rules = [aws_sg_rule(variants["/32"], port) for port in common_ports]
        rules.append(
            {
                **aws_sg_rule(variants["/24"]),
                "Description": "/24 subnet - all traffic",
            }
        )

        print(json.dumps(rules, indent=4))

    print("=" * 60)
    print("  Tip: Use /32 for a single IP, /24 for your whole subnet.")
    print("=" * 60)


if __name__ == "__main__":
    main()
