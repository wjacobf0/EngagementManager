"""Parse nmap XML output (`nmap -oX`) into structured host/service records.

Uses defusedxml to parse untrusted scan files safely (XXE / entity-expansion
protection), since uploads are attacker-adjacent data.
"""
from dataclasses import dataclass, field

from defusedxml import ElementTree as ET


@dataclass
class ParsedService:
    port: int
    protocol: str
    state: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class ParsedHost:
    ip: str
    hostname: str | None = None
    os: str | None = None
    status: str = "unknown"
    services: list[ParsedService] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> list[ParsedHost]:
    root = ET.fromstring(xml_text)
    hosts: list[ParsedHost] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "unknown") if status_el is not None else "unknown"

        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_guess = None
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.get("name")

        parsed = ParsedHost(
            ip=ip,
            hostname=hostname,
            os=os_guess,
            status="alive" if state == "up" else "down",
        )

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_state_el = port_el.find("state")
                port_state = (
                    port_state_el.get("state", "unknown")
                    if port_state_el is not None
                    else "unknown"
                )
                svc_el = port_el.find("service")
                svc = ParsedService(
                    port=int(port_el.get("portid")),
                    protocol=port_el.get("protocol", "tcp"),
                    state=port_state,
                )
                if svc_el is not None:
                    svc.service_name = svc_el.get("name")
                    svc.product = svc_el.get("product")
                    version_bits = [
                        svc_el.get("product"),
                        svc_el.get("version"),
                        svc_el.get("extrainfo"),
                    ]
                    svc.version = svc_el.get("version")
                    svc.banner = " ".join(b for b in version_bits if b) or None
                parsed.services.append(svc)

        hosts.append(parsed)

    return hosts
