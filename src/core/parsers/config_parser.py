"""Parser for importing existing network configurations."""

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from ..models import (
    ACL,
    ACLAction,
    ACLEntry,
    ACLProtocol,
    BGPConfig,
    BGPNeighbor,
    DeviceConfig,
    Interface,
    InterfaceType,
    OSPFConfig,
    OSPFNetwork,
    StaticRoute,
    SwitchportMode,
    Vendor,
    VLAN,
)


@dataclass
class ParseResult:
    """Result of parsing a configuration."""
    config: Optional[DeviceConfig]
    vendor: Optional[Vendor]
    errors: list[str]
    warnings: list[str]


class BaseConfigParser(ABC):
    """Base class for configuration parsers."""

    @abstractmethod
    def parse(self, config_text: str) -> ParseResult:
        """Parse configuration text and return a DeviceConfig."""
        pass

    @abstractmethod
    def detect_vendor(self, config_text: str) -> bool:
        """Check if this parser can handle the given config."""
        pass


class CiscoIOSParser(BaseConfigParser):
    """Parser for Cisco IOS/IOS-XE configurations."""

    def detect_vendor(self, config_text: str) -> bool:
        """Detect if config is Cisco IOS format."""
        ios_indicators = [
            r"^hostname\s+\S+",
            r"^interface\s+(GigabitEthernet|FastEthernet|Ethernet|Loopback)",
            r"^ip route\s+",
            r"^router (ospf|bgp|eigrp)",
            r"^enable secret",
            r"^version\s+\d+\.\d+",
        ]
        for pattern in ios_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False

    def parse(self, config_text: str) -> ParseResult:
        """Parse Cisco IOS configuration."""
        errors = []
        warnings = []

        config = DeviceConfig(
            hostname="",
            vendor=Vendor.CISCO_IOS,
        )

        try:
            # Parse hostname
            hostname_match = re.search(r"^hostname\s+(\S+)", config_text, re.MULTILINE)
            if hostname_match:
                config.hostname = hostname_match.group(1)
            else:
                warnings.append("No hostname found in configuration")

            # Parse domain name
            domain_match = re.search(r"^ip domain[- ]name\s+(\S+)", config_text, re.MULTILINE)
            if domain_match:
                config.domain_name = domain_match.group(1)

            # Parse enable secret
            secret_match = re.search(r"^enable secret\s+\d*\s*(\S+)", config_text, re.MULTILINE)
            if secret_match:
                config.enable_secret = secret_match.group(1)

            # Parse DNS servers
            dns_matches = re.findall(r"^ip name-server\s+(.+)$", config_text, re.MULTILINE)
            for match in dns_matches:
                for server in match.split():
                    if self._is_valid_ip(server):
                        config.dns_servers.append(server)

            # Parse NTP servers (can be IP addresses or hostnames)
            ntp_matches = re.findall(r"^ntp server\s+(\S+)", config_text, re.MULTILINE)
            config.ntp_servers = ntp_matches

            # Parse banner
            banner_match = re.search(
                r"^banner motd\s*(.)(.*?)\1",
                config_text,
                re.MULTILINE | re.DOTALL
            )
            if banner_match:
                config.banner_motd = banner_match.group(2).strip()

            # Parse VLANs
            config.vlans = self._parse_vlans(config_text)

            # Parse interfaces
            config.interfaces = self._parse_interfaces(config_text)

            # Parse ACLs
            config.acls = self._parse_acls(config_text)

            # Parse static routes
            config.static_routes = self._parse_static_routes(config_text)

            # Parse OSPF
            config.ospf = self._parse_ospf(config_text)

            # Parse BGP
            config.bgp = self._parse_bgp(config_text)

        except Exception as e:
            errors.append(f"Parse error: {str(e)}")

        return ParseResult(
            config=config if not errors else None,
            vendor=Vendor.CISCO_IOS,
            errors=errors,
            warnings=warnings,
        )

    def _parse_vlans(self, config_text: str) -> list[VLAN]:
        """Parse VLAN definitions."""
        vlans = []
        vlan_pattern = re.compile(
            r"^vlan\s+(\d+)\s*\n((?:\s+.+\n)*)",
            re.MULTILINE
        )

        for match in vlan_pattern.finditer(config_text):
            vlan_id = int(match.group(1))
            vlan_block = match.group(2)

            name = f"VLAN{vlan_id}"
            name_match = re.search(r"name\s+(\S+)", vlan_block)
            if name_match:
                name = name_match.group(1)

            vlans.append(VLAN(vlan_id=vlan_id, name=name))

        return vlans

    def _parse_interfaces(self, config_text: str) -> list[Interface]:
        """Parse interface configurations."""
        interfaces = []
        iface_pattern = re.compile(
            r"^interface\s+(\S+)\s*\n((?:\s+.+\n)*)",
            re.MULTILINE
        )

        for match in iface_pattern.finditer(config_text):
            iface_name = match.group(1)
            iface_block = match.group(2)

            iface = Interface(
                name=iface_name,
                interface_type=self._detect_interface_type(iface_name),
            )

            # Description
            desc_match = re.search(r"description\s+(.+)", iface_block)
            if desc_match:
                iface.description = desc_match.group(1).strip()

            # IP address
            ip_match = re.search(
                r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                iface_block
            )
            if ip_match:
                iface.ip_address = ip_match.group(1)
                iface.subnet_mask = ip_match.group(2)

            # Shutdown status
            iface.enabled = "shutdown" not in iface_block or "no shutdown" in iface_block

            # VLAN configuration
            access_vlan = re.search(r"switchport access vlan\s+(\d+)", iface_block)
            if access_vlan:
                iface.vlan_id = int(access_vlan.group(1))

            # Trunk configuration
            if "switchport mode trunk" in iface_block:
                iface.is_trunk = True
                allowed = re.search(r"switchport trunk allowed vlan\s+(.+)", iface_block)
                if allowed:
                    iface.trunk_allowed_vlans = allowed.group(1).strip()
                native = re.search(r"switchport trunk native vlan\s+(\d+)", iface_block)
                if native:
                    iface.native_vlan = int(native.group(1))

            # MTU
            mtu_match = re.search(r"mtu\s+(\d+)", iface_block)
            if mtu_match:
                iface.mtu = int(mtu_match.group(1))

            # Channel group
            channel_match = re.search(r"channel-group\s+(\d+)", iface_block)
            if channel_match:
                iface.channel_group = int(channel_match.group(1))

            interfaces.append(iface)

        return interfaces

    def _parse_acls(self, config_text: str) -> list[ACL]:
        """Parse ACL configurations."""
        acls = []

        # Extended ACLs
        extended_pattern = re.compile(
            r"^ip access-list extended\s+(\S+)\s*\n((?:\s+.+\n)*)",
            re.MULTILINE
        )

        for match in extended_pattern.finditer(config_text):
            acl_name = match.group(1)
            acl_block = match.group(2)
            acl = ACL(name=acl_name, is_extended=True)

            for line in acl_block.split("\n"):
                entry = self._parse_acl_entry(line.strip())
                if entry:
                    acl.entries.append(entry)

            acls.append(acl)

        # Standard ACLs
        standard_pattern = re.compile(
            r"^ip access-list standard\s+(\S+)\s*\n((?:\s+.+\n)*)",
            re.MULTILINE
        )

        for match in standard_pattern.finditer(config_text):
            acl_name = match.group(1)
            acl_block = match.group(2)
            acl = ACL(name=acl_name, is_extended=False)

            for line in acl_block.split("\n"):
                entry = self._parse_acl_entry(line.strip(), is_standard=True)
                if entry:
                    acl.entries.append(entry)

            acls.append(acl)

        return acls

    def _parse_acl_entry(self, line: str, is_standard: bool = False) -> Optional[ACLEntry]:
        """Parse a single ACL entry."""
        if not line or line.startswith("!"):
            return None

        # Handle remarks
        remark_match = re.match(r"(\d+)?\s*remark\s+(.+)", line)
        if remark_match:
            seq = int(remark_match.group(1)) if remark_match.group(1) else 10
            return ACLEntry(
                sequence=seq,
                action=ACLAction.PERMIT,
                protocol=ACLProtocol.IP,
                source="any",
                remark=remark_match.group(2),
            )

        # Parse regular entry
        parts = line.split()
        if len(parts) < 3:
            return None

        try:
            # Check for sequence number
            idx = 0
            if parts[0].isdigit():
                seq = int(parts[0])
                idx = 1
            else:
                seq = 10

            action_str = parts[idx].lower()
            if action_str not in ("permit", "deny"):
                return None

            action = ACLAction.PERMIT if action_str == "permit" else ACLAction.DENY
            idx += 1

            # Protocol
            protocol_str = parts[idx].lower() if idx < len(parts) else "ip"
            protocol = ACLProtocol.IP
            for p in ACLProtocol:
                if p.value == protocol_str:
                    protocol = p
                    break
            idx += 1

            # Source
            source = parts[idx] if idx < len(parts) else "any"
            idx += 1

            # Source wildcard
            source_wildcard = "0.0.0.0"
            if idx < len(parts) and self._is_valid_ip(parts[idx]):
                source_wildcard = parts[idx]
                idx += 1

            # For extended ACLs, get destination
            destination = "any"
            destination_wildcard = "0.0.0.0"
            if not is_standard and idx < len(parts):
                destination = parts[idx]
                idx += 1
                if idx < len(parts) and self._is_valid_ip(parts[idx]):
                    destination_wildcard = parts[idx]

            return ACLEntry(
                sequence=seq,
                action=action,
                protocol=protocol,
                source=source,
                source_wildcard=source_wildcard,
                destination=destination,
                destination_wildcard=destination_wildcard,
                log="log" in line.lower(),
            )

        except (ValueError, IndexError):
            return None

    def _parse_static_routes(self, config_text: str) -> list[StaticRoute]:
        """Parse static route configurations."""
        routes = []
        route_pattern = re.compile(
            r"^ip route\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(?:\s+(\d+))?(?:\s+name\s+(\S+))?",
            re.MULTILINE
        )

        for match in route_pattern.finditer(config_text):
            routes.append(StaticRoute(
                destination=match.group(1),
                mask=match.group(2),
                next_hop=match.group(3),
                admin_distance=int(match.group(4)) if match.group(4) else 1,
                name=match.group(5) or "",
            ))

        return routes

    def _parse_ospf(self, config_text: str) -> Optional[OSPFConfig]:
        """Parse OSPF configuration."""
        ospf_match = re.search(
            r"^router ospf\s+(\d+)\s*\n((?:\s+.+\n)*)",
            config_text,
            re.MULTILINE
        )

        if not ospf_match:
            return None

        process_id = int(ospf_match.group(1))
        ospf_block = ospf_match.group(2)

        ospf = OSPFConfig(process_id=process_id)

        # Router ID
        rid_match = re.search(r"router-id\s+(\S+)", ospf_block)
        if rid_match:
            ospf.router_id = rid_match.group(1)

        # Reference bandwidth
        bw_match = re.search(r"auto-cost reference-bandwidth\s+(\d+)", ospf_block)
        if bw_match:
            ospf.reference_bandwidth = int(bw_match.group(1))

        # Networks
        network_pattern = re.compile(
            r"network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\d+)"
        )
        for match in network_pattern.finditer(ospf_block):
            ospf.networks.append(OSPFNetwork(
                network=match.group(1),
                wildcard=match.group(2),
                area=int(match.group(3)),
            ))

        # Passive interfaces
        passive_pattern = re.compile(r"passive-interface\s+(\S+)")
        for match in passive_pattern.finditer(ospf_block):
            ospf.passive_interfaces.append(match.group(1))

        # Default information originate
        ospf.default_information_originate = "default-information originate" in ospf_block

        return ospf

    def _parse_bgp(self, config_text: str) -> Optional[BGPConfig]:
        """Parse BGP configuration."""
        bgp_match = re.search(
            r"^router bgp\s+(\d+)\s*\n((?:\s+.+\n)*)",
            config_text,
            re.MULTILINE
        )

        if not bgp_match:
            return None

        local_as = int(bgp_match.group(1))
        bgp_block = bgp_match.group(2)

        bgp = BGPConfig(local_as=local_as)

        # Router ID
        rid_match = re.search(r"router-id\s+(\S+)", bgp_block)
        if rid_match:
            bgp.router_id = rid_match.group(1)
        else:
            rid_match = re.search(r"bgp router-id\s+(\S+)", bgp_block)
            if rid_match:
                bgp.router_id = rid_match.group(1)

        # Log neighbor changes
        bgp.log_neighbor_changes = "log-neighbor-changes" in bgp_block

        # Networks
        network_pattern = re.compile(r"^\s+network\s+(\S+)", re.MULTILINE)
        for match in network_pattern.finditer(bgp_block):
            bgp.networks.append(match.group(1))

        # Neighbors
        neighbor_pattern = re.compile(r"neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)")
        for match in neighbor_pattern.finditer(bgp_block):
            neighbor_ip = match.group(1)
            remote_as = int(match.group(2))

            neighbor = BGPNeighbor(ip_address=neighbor_ip, remote_as=remote_as)

            # Description
            desc_match = re.search(
                rf"neighbor\s+{re.escape(neighbor_ip)}\s+description\s+(.+)",
                bgp_block
            )
            if desc_match:
                neighbor.description = desc_match.group(1).strip()

            # Password
            pass_match = re.search(
                rf"neighbor\s+{re.escape(neighbor_ip)}\s+password\s+(\S+)",
                bgp_block
            )
            if pass_match:
                neighbor.password = pass_match.group(1)

            # Update source
            source_match = re.search(
                rf"neighbor\s+{re.escape(neighbor_ip)}\s+update-source\s+(\S+)",
                bgp_block
            )
            if source_match:
                neighbor.update_source = source_match.group(1)

            # EBGP multihop
            multihop_match = re.search(
                rf"neighbor\s+{re.escape(neighbor_ip)}\s+ebgp-multihop\s+(\d+)",
                bgp_block
            )
            if multihop_match:
                neighbor.ebgp_multihop = int(multihop_match.group(1))

            bgp.neighbors.append(neighbor)

        return bgp

    def _detect_interface_type(self, name: str) -> InterfaceType:
        """Detect interface type from name."""
        name_lower = name.lower()
        if "gigabit" in name_lower or name_lower.startswith("gi"):
            return InterfaceType.GIGABIT
        elif "tengigabit" in name_lower or name_lower.startswith("te"):
            return InterfaceType.TEN_GIGABIT
        elif "loopback" in name_lower or name_lower.startswith("lo"):
            return InterfaceType.LOOPBACK
        elif "vlan" in name_lower:
            return InterfaceType.VLAN
        elif "port-channel" in name_lower or name_lower.startswith("po"):
            return InterfaceType.PORT_CHANNEL
        elif "mgmt" in name_lower or "management" in name_lower:
            return InterfaceType.MGMT
        else:
            return InterfaceType.ETHERNET

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False


class JuniperJunosParser(BaseConfigParser):
    """Parser for Juniper Junos configurations."""

    def detect_vendor(self, config_text: str) -> bool:
        """Detect if config is Juniper Junos format."""
        junos_indicators = [
            r"system\s*\{",
            r"interfaces\s*\{",
            r"host-name\s+\S+;",
            r"protocols\s*\{",
            r"routing-options\s*\{",
            r"vlans\s*\{",
        ]
        for pattern in junos_indicators:
            if re.search(pattern, config_text, re.MULTILINE):
                return True
        return False

    def parse(self, config_text: str) -> ParseResult:
        """Parse Juniper Junos configuration."""
        errors = []
        warnings = []

        config = DeviceConfig(
            hostname="",
            vendor=Vendor.JUNIPER_JUNOS,
        )

        try:
            # Parse system block
            self._parse_system_block(config_text, config, warnings)

            # Parse interfaces
            config.interfaces = self._parse_interfaces(config_text)

            # Parse VLANs
            config.vlans = self._parse_vlans(config_text)

            # Parse static routes
            config.static_routes = self._parse_static_routes(config_text)

            # Parse OSPF
            config.ospf = self._parse_ospf(config_text)

            # Parse BGP
            config.bgp = self._parse_bgp(config_text)

        except Exception as e:
            errors.append(f"Parse error: {str(e)}")

        return ParseResult(
            config=config if not errors else None,
            vendor=Vendor.JUNIPER_JUNOS,
            errors=errors,
            warnings=warnings,
        )

    def _parse_system_block(self, config_text: str, config: DeviceConfig, warnings: list) -> None:
        """Parse the system configuration block."""
        system_match = re.search(
            r"system\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
            config_text,
            re.DOTALL
        )

        if not system_match:
            warnings.append("No system block found in configuration")
            return

        system_block = system_match.group(1)

        # Hostname
        hostname_match = re.search(r"host-name\s+(\S+);", system_block)
        if hostname_match:
            config.hostname = hostname_match.group(1)
        else:
            warnings.append("No hostname found in configuration")

        # Domain name
        domain_match = re.search(r"domain-name\s+(\S+);", system_block)
        if domain_match:
            config.domain_name = domain_match.group(1)

        # Name servers (DNS)
        nameserver_block = re.search(r"name-server\s*\{([^}]*)\}", system_block)
        if nameserver_block:
            servers = re.findall(r"(\d+\.\d+\.\d+\.\d+);", nameserver_block.group(1))
            config.dns_servers = servers
        else:
            # Single name-server format
            servers = re.findall(r"name-server\s+(\d+\.\d+\.\d+\.\d+);", system_block)
            config.dns_servers = servers

        # NTP servers
        ntp_block = re.search(r"ntp\s*\{([^}]*)\}", system_block)
        if ntp_block:
            servers = re.findall(r"server\s+(\S+);", ntp_block.group(1))
            config.ntp_servers = servers

        # Login banner (motd)
        banner_match = re.search(r'login\s*\{[^}]*message\s+"([^"]+)"', system_block, re.DOTALL)
        if banner_match:
            config.banner_motd = banner_match.group(1)

    def _parse_interfaces(self, config_text: str) -> list[Interface]:
        """Parse interface configurations."""
        interfaces = []

        # Find the interfaces block using brace counting
        interfaces_match = re.search(r"interfaces\s*\{", config_text)
        if not interfaces_match:
            return interfaces

        interfaces_block = self._extract_brace_block(config_text, interfaces_match.start())
        if not interfaces_block:
            return interfaces

        # Find interface names at the start of blocks within interfaces { }
        # Skip the outer "interfaces {" wrapper
        inner_content = interfaces_block[1:-1]  # Remove outer braces

        iface_starts = list(re.finditer(r"^\s*([\w\-/]+)\s*\{", inner_content, re.MULTILINE))

        for match in iface_starts:
            iface_name = match.group(1)

            # Skip non-interface entries
            if iface_name in ("apply-groups", "apply-macro"):
                continue

            # Extract this interface's block
            iface_block = self._extract_brace_block(inner_content, match.start())
            if not iface_block:
                continue

            iface = Interface(
                name=iface_name,
                interface_type=self._detect_interface_type(iface_name),
            )

            # Description
            desc_match = re.search(r'description\s+"([^"]+)"', iface_block)
            if desc_match:
                iface.description = desc_match.group(1)
            else:
                desc_match = re.search(r"description\s+(\S+);", iface_block)
                if desc_match:
                    iface.description = desc_match.group(1)

            # IP address - look anywhere in the interface block
            ip_match = re.search(r"address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", iface_block)
            if ip_match:
                iface.ip_address = ip_match.group(1)
                iface.subnet_mask = self._cidr_to_netmask(int(ip_match.group(2)))

            # Check for VLAN membership
            vlan_match = re.search(r"members\s+(\S+);", iface_block)
            if vlan_match:
                vlan_name = vlan_match.group(1)
                if not iface.description:
                    iface.description = f"VLAN: {vlan_name}"

            # MTU
            mtu_match = re.search(r"mtu\s+(\d+);", iface_block)
            if mtu_match:
                iface.mtu = int(mtu_match.group(1))

            # Disable status
            iface.enabled = "disable;" not in iface_block

            # Aggregated ethernet (port-channel equivalent)
            ae_match = re.search(r"802.3ad\s+(\S+);", iface_block)
            if ae_match:
                ae_name = ae_match.group(1)
                ae_num = re.search(r"ae(\d+)", ae_name)
                if ae_num:
                    iface.channel_group = int(ae_num.group(1))

            interfaces.append(iface)

        return interfaces

    def _extract_brace_block(self, text: str, start_pos: int) -> Optional[str]:
        """Extract a complete brace-delimited block starting at position."""
        brace_pos = text.find("{", start_pos)
        if brace_pos == -1:
            return None

        depth = 0
        for i in range(brace_pos, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    return text[brace_pos:i + 1]

        return None

    def _parse_vlans(self, config_text: str) -> list[VLAN]:
        """Parse VLAN definitions."""
        vlans = []

        vlans_match = re.search(
            r"vlans\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
            config_text,
            re.DOTALL
        )

        if not vlans_match:
            return vlans

        vlans_block = vlans_match.group(1)

        # Match individual VLAN blocks
        vlan_pattern = re.compile(r"(\S+)\s*\{([^{}]*)\}", re.DOTALL)

        for match in vlan_pattern.finditer(vlans_block):
            vlan_name = match.group(1)
            vlan_block = match.group(2)

            # Get VLAN ID
            vlan_id_match = re.search(r"vlan-id\s+(\d+);", vlan_block)
            if vlan_id_match:
                vlans.append(VLAN(
                    vlan_id=int(vlan_id_match.group(1)),
                    name=vlan_name,
                ))

        return vlans

    def _parse_static_routes(self, config_text: str) -> list[StaticRoute]:
        """Parse static route configurations."""
        routes = []

        routing_match = re.search(
            r"routing-options\s*\{([^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*)\}",
            config_text,
            re.DOTALL
        )

        if not routing_match:
            return routes

        routing_block = routing_match.group(1)

        # Find static block
        static_match = re.search(
            r"static\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
            routing_block,
            re.DOTALL
        )

        if not static_match:
            return routes

        static_block = static_match.group(1)

        # Parse routes
        route_pattern = re.compile(
            r"route\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s*(?:\{[^}]*next-hop\s+(\d+\.\d+\.\d+\.\d+)|next-hop\s+(\d+\.\d+\.\d+\.\d+))",
            re.DOTALL
        )

        for match in route_pattern.finditer(static_block):
            dest = match.group(1)
            prefix = int(match.group(2))
            next_hop = match.group(3) or match.group(4)

            if next_hop:
                routes.append(StaticRoute(
                    destination=dest,
                    mask=self._cidr_to_netmask(prefix),
                    next_hop=next_hop,
                ))

        return routes

    def _parse_ospf(self, config_text: str) -> Optional[OSPFConfig]:
        """Parse OSPF configuration."""
        protocols_match = re.search(
            r"protocols\s*\{([^{}]*(?:\{[^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*\}[^{}]*)*)\}",
            config_text,
            re.DOTALL
        )

        if not protocols_match:
            return None

        protocols_block = protocols_match.group(1)

        ospf_match = re.search(
            r"ospf\s*\{([^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*)\}",
            protocols_block,
            re.DOTALL
        )

        if not ospf_match:
            return None

        ospf_block = ospf_match.group(1)
        ospf = OSPFConfig(process_id=0)  # Junos doesn't use process IDs the same way

        # Router ID from routing-options
        rid_match = re.search(r"router-id\s+(\d+\.\d+\.\d+\.\d+);", config_text)
        if rid_match:
            ospf.router_id = rid_match.group(1)

        # Reference bandwidth
        bw_match = re.search(r"reference-bandwidth\s+(\S+);", ospf_block)
        if bw_match:
            bw_str = bw_match.group(1)
            # Handle values like "10g" or "1000m"
            if bw_str.endswith("g"):
                ospf.reference_bandwidth = int(bw_str[:-1]) * 1000
            elif bw_str.endswith("m"):
                ospf.reference_bandwidth = int(bw_str[:-1])
            else:
                try:
                    ospf.reference_bandwidth = int(bw_str)
                except ValueError:
                    pass

        # Parse areas and their interfaces
        area_pattern = re.compile(
            r"area\s+(\S+)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
            re.DOTALL
        )

        for area_match in area_pattern.finditer(ospf_block):
            area_id = area_match.group(1)
            area_block = area_match.group(2)

            # Convert area to integer if possible
            try:
                if "." in area_id:
                    # Dotted format like 0.0.0.0
                    area_num = int(area_id.split(".")[-1])
                else:
                    area_num = int(area_id)
            except ValueError:
                area_num = 0

            # Find interfaces in this area
            iface_pattern = re.compile(r"interface\s+(\S+)")
            for iface_match in iface_pattern.finditer(area_block):
                iface_name = iface_match.group(1).rstrip(";")
                # Create a network entry (approximation)
                ospf.networks.append(OSPFNetwork(
                    network="0.0.0.0",  # Junos doesn't specify networks the same way
                    wildcard="0.0.0.0",
                    area=area_num,
                ))

                # Check for passive
                if "passive" in area_block:
                    ospf.passive_interfaces.append(iface_name)

        return ospf if ospf.networks else None

    def _parse_bgp(self, config_text: str) -> Optional[BGPConfig]:
        """Parse BGP configuration."""
        protocols_match = re.search(
            r"protocols\s*\{([^{}]*(?:\{[^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*\}[^{}]*)*)\}",
            config_text,
            re.DOTALL
        )

        if not protocols_match:
            return None

        protocols_block = protocols_match.group(1)

        bgp_match = re.search(
            r"bgp\s*\{([^{}]*(?:\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}[^{}]*)*)\}",
            protocols_block,
            re.DOTALL
        )

        if not bgp_match:
            return None

        bgp_block = bgp_match.group(1)

        # Get local AS from routing-options
        as_match = re.search(r"autonomous-system\s+(\d+);", config_text)
        if not as_match:
            return None

        local_as = int(as_match.group(1))
        bgp = BGPConfig(local_as=local_as)

        # Router ID
        rid_match = re.search(r"router-id\s+(\d+\.\d+\.\d+\.\d+);", config_text)
        if rid_match:
            bgp.router_id = rid_match.group(1)

        # Parse groups and neighbors
        group_pattern = re.compile(
            r"group\s+(\S+)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
            re.DOTALL
        )

        for group_match in group_pattern.finditer(bgp_block):
            group_name = group_match.group(1)
            group_block = group_match.group(2)

            # Get peer-as for the group
            peer_as_match = re.search(r"peer-as\s+(\d+);", group_block)
            peer_as = int(peer_as_match.group(1)) if peer_as_match else 0

            # Find neighbors in this group
            neighbor_pattern = re.compile(r"neighbor\s+(\d+\.\d+\.\d+\.\d+)")
            for neighbor_match in neighbor_pattern.finditer(group_block):
                neighbor_ip = neighbor_match.group(1)

                neighbor = BGPNeighbor(
                    ip_address=neighbor_ip,
                    remote_as=peer_as,
                    description=group_name,
                )

                # Check for authentication
                auth_match = re.search(r"authentication-key\s+\"([^\"]+)\"", group_block)
                if auth_match:
                    neighbor.password = auth_match.group(1)

                # Multihop
                multihop_match = re.search(r"multihop\s*\{[^}]*ttl\s+(\d+)", group_block)
                if multihop_match:
                    neighbor.ebgp_multihop = int(multihop_match.group(1))
                elif "multihop" in group_block:
                    neighbor.ebgp_multihop = 2

                # Local address (update-source equivalent)
                local_match = re.search(r"local-address\s+(\S+);", group_block)
                if local_match:
                    neighbor.update_source = local_match.group(1)

                bgp.neighbors.append(neighbor)

        return bgp if bgp.neighbors or as_match else None

    def _detect_interface_type(self, name: str) -> InterfaceType:
        """Detect interface type from Junos name."""
        name_lower = name.lower()
        if name_lower.startswith("ge-"):
            return InterfaceType.GIGABIT
        elif name_lower.startswith("xe-"):
            return InterfaceType.TEN_GIGABIT
        elif name_lower.startswith("et-"):
            return InterfaceType.HUNDRED_GIGABIT
        elif name_lower.startswith("lo"):
            return InterfaceType.LOOPBACK
        elif name_lower.startswith("ae"):
            return InterfaceType.PORT_CHANNEL
        elif name_lower.startswith("vlan") or name_lower.startswith("irb"):
            return InterfaceType.VLAN
        elif name_lower.startswith("em") or name_lower.startswith("fxp"):
            return InterfaceType.MGMT
        else:
            return InterfaceType.ETHERNET

    @staticmethod
    def _cidr_to_netmask(prefix: int) -> str:
        """Convert CIDR prefix to dotted decimal netmask."""
        if prefix < 0 or prefix > 32:
            return "255.255.255.255"
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"


class SONiCParser(BaseConfigParser):
    """Parser for SONiC config_db.json configurations."""

    def detect_vendor(self, config_text: str) -> bool:
        """Detect if config is SONiC JSON format."""
        # Try to parse as JSON and look for SONiC-specific tables
        try:
            data = json.loads(config_text)
            sonic_tables = [
                "DEVICE_METADATA",
                "PORT",
                "INTERFACE",
                "VLAN",
                "BGP_NEIGHBOR",
                "LOOPBACK_INTERFACE",
            ]
            # Check if any SONiC-specific tables exist
            return any(table in data for table in sonic_tables)
        except (json.JSONDecodeError, TypeError):
            return False

    def parse(self, config_text: str) -> ParseResult:
        """Parse SONiC config_db.json configuration."""
        errors = []
        warnings = []

        config = DeviceConfig(
            hostname="",
            vendor=Vendor.SONIC,
        )

        try:
            data = json.loads(config_text)

            # Parse DEVICE_METADATA
            self._parse_device_metadata(data, config, warnings)

            # Parse interfaces (PORT, INTERFACE, LOOPBACK_INTERFACE)
            config.interfaces = self._parse_interfaces(data)

            # Parse VLANs
            config.vlans = self._parse_vlans(data)

            # Parse VLAN members and update interfaces
            self._parse_vlan_members(data, config)

            # Parse BGP
            config.bgp = self._parse_bgp(data)

            # Parse static routes
            config.static_routes = self._parse_static_routes(data)

            # Parse ACLs
            config.acls = self._parse_acls(data)

            # Parse NTP servers
            config.ntp_servers = self._parse_ntp_servers(data)

            # Parse DNS servers
            config.dns_servers = self._parse_dns_servers(data)

        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {str(e)}")
        except Exception as e:
            errors.append(f"Parse error: {str(e)}")

        return ParseResult(
            config=config if not errors else None,
            vendor=Vendor.SONIC,
            errors=errors,
            warnings=warnings,
        )

    def _parse_device_metadata(self, data: dict, config: DeviceConfig, warnings: list) -> None:
        """Parse DEVICE_METADATA table."""
        metadata = data.get("DEVICE_METADATA", {}).get("localhost", {})

        if "hostname" in metadata:
            config.hostname = metadata["hostname"]
        else:
            warnings.append("No hostname found in DEVICE_METADATA")

        # BGP ASN is often stored in metadata
        if "bgp_asn" in metadata:
            try:
                asn = int(metadata["bgp_asn"])
                if config.bgp is None:
                    config.bgp = BGPConfig(local_as=asn)
                else:
                    config.bgp.local_as = asn
            except ValueError:
                pass

    def _parse_interfaces(self, data: dict) -> list[Interface]:
        """Parse PORT, INTERFACE, LOOPBACK_INTERFACE tables."""
        interfaces = []
        processed_names = set()

        # Parse PORT table (physical interfaces)
        ports = data.get("PORT", {})
        for port_name, port_config in ports.items():
            iface = Interface(
                name=port_name,
                interface_type=self._detect_interface_type(port_name),
                enabled=port_config.get("admin_status", "up") == "up",
                description=port_config.get("description", ""),
            )

            # MTU
            if "mtu" in port_config:
                try:
                    iface.mtu = int(port_config["mtu"])
                except ValueError:
                    pass

            # Speed
            if "speed" in port_config:
                iface.speed = port_config["speed"]

            interfaces.append(iface)
            processed_names.add(port_name)

        # Parse INTERFACE table (L3 addresses on physical interfaces)
        interface_table = data.get("INTERFACE", {})
        for key in interface_table.keys():
            if "|" in key:
                iface_name, ip_prefix = key.split("|", 1)
                # Find existing interface or create new one
                existing = next((i for i in interfaces if i.name == iface_name), None)
                if existing:
                    # Parse IP/prefix
                    if "/" in ip_prefix:
                        ip, prefix = ip_prefix.split("/")
                        existing.ip_address = ip
                        existing.subnet_mask = self._cidr_to_netmask(int(prefix))
                elif iface_name not in processed_names:
                    # Create new interface
                    if "/" in ip_prefix:
                        ip, prefix = ip_prefix.split("/")
                        iface = Interface(
                            name=iface_name,
                            interface_type=self._detect_interface_type(iface_name),
                            ip_address=ip,
                            subnet_mask=self._cidr_to_netmask(int(prefix)),
                        )
                        interfaces.append(iface)
                        processed_names.add(iface_name)

        # Parse LOOPBACK_INTERFACE table
        loopback_table = data.get("LOOPBACK_INTERFACE", {})
        for key in loopback_table.keys():
            if "|" in key:
                iface_name, ip_prefix = key.split("|", 1)
                if iface_name not in processed_names:
                    if "/" in ip_prefix:
                        ip, prefix = ip_prefix.split("/")
                        iface = Interface(
                            name=iface_name,
                            interface_type=InterfaceType.LOOPBACK,
                            ip_address=ip,
                            subnet_mask=self._cidr_to_netmask(int(prefix)),
                        )
                        interfaces.append(iface)
                        processed_names.add(iface_name)

        # Parse VLAN_INTERFACE table
        vlan_iface_table = data.get("VLAN_INTERFACE", {})
        for key in vlan_iface_table.keys():
            if "|" in key:
                iface_name, ip_prefix = key.split("|", 1)
                if iface_name not in processed_names:
                    if "/" in ip_prefix:
                        ip, prefix = ip_prefix.split("/")
                        iface = Interface(
                            name=iface_name,
                            interface_type=InterfaceType.VLAN,
                            ip_address=ip,
                            subnet_mask=self._cidr_to_netmask(int(prefix)),
                        )
                        interfaces.append(iface)
                        processed_names.add(iface_name)

        # Parse PORTCHANNEL table
        portchannel_table = data.get("PORTCHANNEL", {})
        for pc_name, pc_config in portchannel_table.items():
            if pc_name not in processed_names:
                iface = Interface(
                    name=pc_name,
                    interface_type=InterfaceType.PORT_CHANNEL,
                    enabled=pc_config.get("admin_status", "up") == "up",
                )
                if "mtu" in pc_config:
                    try:
                        iface.mtu = int(pc_config["mtu"])
                    except ValueError:
                        pass
                interfaces.append(iface)
                processed_names.add(pc_name)

        # Parse PORTCHANNEL_INTERFACE table for IPs
        pc_iface_table = data.get("PORTCHANNEL_INTERFACE", {})
        for key in pc_iface_table.keys():
            if "|" in key:
                iface_name, ip_prefix = key.split("|", 1)
                existing = next((i for i in interfaces if i.name == iface_name), None)
                if existing and "/" in ip_prefix:
                    ip, prefix = ip_prefix.split("/")
                    existing.ip_address = ip
                    existing.subnet_mask = self._cidr_to_netmask(int(prefix))

        return interfaces

    def _parse_vlans(self, data: dict) -> list[VLAN]:
        """Parse VLAN table."""
        vlans = []
        vlan_table = data.get("VLAN", {})

        for vlan_name, vlan_config in vlan_table.items():
            # Extract VLAN ID from name (e.g., "Vlan1000" -> 1000)
            vlan_id_match = re.search(r"(\d+)", vlan_name)
            if vlan_id_match:
                vlan_id = int(vlan_id_match.group(1))
            elif "vlanid" in vlan_config:
                vlan_id = int(vlan_config["vlanid"])
            else:
                continue

            vlans.append(VLAN(
                vlan_id=vlan_id,
                name=vlan_name,
            ))

        return vlans

    def _parse_vlan_members(self, data: dict, config: DeviceConfig) -> None:
        """Parse VLAN_MEMBER table and update interfaces."""
        vlan_member_table = data.get("VLAN_MEMBER", {})

        for key, member_config in vlan_member_table.items():
            if "|" in key:
                vlan_name, iface_name = key.split("|", 1)
                tagging_mode = member_config.get("tagging_mode", "untagged")

                # Extract VLAN ID
                vlan_id_match = re.search(r"(\d+)", vlan_name)
                if not vlan_id_match:
                    continue
                vlan_id = int(vlan_id_match.group(1))

                # Find the interface
                existing = next((i for i in config.interfaces if i.name == iface_name), None)
                if existing:
                    if tagging_mode == "untagged":
                        existing.vlan_id = vlan_id
                        existing.switchport_mode = SwitchportMode.ACCESS
                    elif tagging_mode == "tagged":
                        existing.is_trunk = True
                        existing.switchport_mode = SwitchportMode.TRUNK
                        if existing.trunk_allowed_vlans:
                            existing.trunk_allowed_vlans += f",{vlan_id}"
                        else:
                            existing.trunk_allowed_vlans = str(vlan_id)

    def _parse_bgp(self, data: dict) -> Optional[BGPConfig]:
        """Parse BGP_NEIGHBOR table."""
        neighbor_table = data.get("BGP_NEIGHBOR", {})
        if not neighbor_table:
            return None

        # Get ASN from DEVICE_METADATA if available
        metadata = data.get("DEVICE_METADATA", {}).get("localhost", {})
        local_as = 65000  # Default
        if "bgp_asn" in metadata:
            try:
                local_as = int(metadata["bgp_asn"])
            except ValueError:
                pass

        bgp = BGPConfig(local_as=local_as)

        for neighbor_ip, neighbor_config in neighbor_table.items():
            # Skip IPv6 neighbors for now
            if ":" in neighbor_ip:
                continue

            try:
                # SONiC uses rmt_asn, but support asn for compatibility
                remote_as = int(neighbor_config.get("rmt_asn", neighbor_config.get("asn", 0)))
            except ValueError:
                continue

            neighbor = BGPNeighbor(
                ip_address=neighbor_ip,
                remote_as=remote_as,
                description=neighbor_config.get("name", ""),
            )

            # Update source (local_addr in SONiC)
            if "local_addr" in neighbor_config:
                neighbor.update_source = neighbor_config["local_addr"]

            bgp.neighbors.append(neighbor)

        return bgp if bgp.neighbors else None

    def _parse_static_routes(self, data: dict) -> list[StaticRoute]:
        """Parse STATIC_ROUTE table."""
        routes = []
        route_table = data.get("STATIC_ROUTE", {})

        for prefix, route_config in route_table.items():
            if "/" in prefix:
                dest, cidr = prefix.split("/")
                mask = self._cidr_to_netmask(int(cidr))
                next_hop = route_config.get("nexthop", "")

                if next_hop:
                    route = StaticRoute(
                        destination=dest,
                        mask=mask,
                        next_hop=next_hop,
                    )

                    # Admin distance
                    if "distance" in route_config:
                        try:
                            route.admin_distance = int(route_config["distance"])
                        except ValueError:
                            pass

                    routes.append(route)

        return routes

    def _parse_acls(self, data: dict) -> list[ACL]:
        """Parse ACL_TABLE and ACL_RULE tables."""
        acls = []
        acl_table = data.get("ACL_TABLE", {})
        acl_rule_table = data.get("ACL_RULE", {})

        for acl_name, acl_config in acl_table.items():
            acl = ACL(
                name=acl_name,
                is_extended=acl_config.get("type", "L3") == "L3",
            )

            # Find rules for this ACL
            for rule_key, rule_config in acl_rule_table.items():
                if rule_key.startswith(f"{acl_name}|"):
                    # Extract sequence from rule name
                    seq_match = re.search(r"RULE_(\d+)", rule_key)
                    sequence = int(seq_match.group(1)) if seq_match else 10

                    # Determine action
                    packet_action = rule_config.get("PACKET_ACTION", "DROP")
                    action = ACLAction.PERMIT if packet_action in ("FORWARD", "ACCEPT") else ACLAction.DENY

                    # Determine protocol
                    ip_protocol = rule_config.get("IP_PROTOCOL", "")
                    if ip_protocol == "6":
                        protocol = ACLProtocol.TCP
                    elif ip_protocol == "17":
                        protocol = ACLProtocol.UDP
                    elif ip_protocol == "1":
                        protocol = ACLProtocol.ICMP
                    else:
                        protocol = ACLProtocol.IP

                    # Source
                    src_ip = rule_config.get("SRC_IP", "any")
                    if "/" in src_ip:
                        source, src_prefix = src_ip.split("/")
                        source_wildcard = self._cidr_to_wildcard(int(src_prefix))
                    else:
                        source = src_ip
                        source_wildcard = "0.0.0.0"

                    # Destination
                    dst_ip = rule_config.get("DST_IP", "any")
                    if "/" in dst_ip:
                        destination, dst_prefix = dst_ip.split("/")
                        destination_wildcard = self._cidr_to_wildcard(int(dst_prefix))
                    else:
                        destination = dst_ip
                        destination_wildcard = "0.0.0.0"

                    entry = ACLEntry(
                        sequence=sequence,
                        action=action,
                        protocol=protocol,
                        source=source,
                        source_wildcard=source_wildcard,
                        destination=destination,
                        destination_wildcard=destination_wildcard,
                        source_port=rule_config.get("L4_SRC_PORT"),
                        destination_port=rule_config.get("L4_DST_PORT"),
                    )
                    acl.entries.append(entry)

            # Sort entries by sequence
            acl.entries.sort(key=lambda e: e.sequence)
            acls.append(acl)

        return acls

    def _parse_ntp_servers(self, data: dict) -> list[str]:
        """Parse NTP_SERVER table."""
        ntp_table = data.get("NTP_SERVER", {})
        return list(ntp_table.keys())

    def _parse_dns_servers(self, data: dict) -> list[str]:
        """Parse DNS_NAMESERVER table."""
        dns_table = data.get("DNS_NAMESERVER", {})
        return list(dns_table.keys())

    def _detect_interface_type(self, name: str) -> InterfaceType:
        """Detect interface type from SONiC name."""
        name_lower = name.lower()
        if name_lower.startswith("ethernet"):
            return InterfaceType.ETHERNET
        elif name_lower.startswith("loopback"):
            return InterfaceType.LOOPBACK
        elif name_lower.startswith("portchannel"):
            return InterfaceType.PORT_CHANNEL
        elif name_lower.startswith("vlan"):
            return InterfaceType.VLAN
        elif name_lower.startswith("eth") or name_lower.startswith("mgmt"):
            return InterfaceType.MGMT
        else:
            return InterfaceType.ETHERNET

    @staticmethod
    def _cidr_to_netmask(prefix: int) -> str:
        """Convert CIDR prefix to dotted decimal netmask."""
        if prefix < 0 or prefix > 32:
            return "255.255.255.255"
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        return f"{(mask >> 24) & 0xFF}.{(mask >> 16) & 0xFF}.{(mask >> 8) & 0xFF}.{mask & 0xFF}"

    @staticmethod
    def _cidr_to_wildcard(prefix: int) -> str:
        """Convert CIDR prefix to wildcard mask."""
        if prefix < 0 or prefix > 32:
            return "0.0.0.0"
        wildcard = (0xFFFFFFFF >> prefix) & 0xFFFFFFFF
        return f"{(wildcard >> 24) & 0xFF}.{(wildcard >> 16) & 0xFF}.{(wildcard >> 8) & 0xFF}.{wildcard & 0xFF}"


class ConfigParserFactory:
    """Factory for creating appropriate config parsers."""

    _parsers = [
        SONiCParser,  # Check SONiC first (JSON format is very specific)
        JuniperJunosParser,  # Check Junos second (more specific patterns)
        CiscoIOSParser,
    ]

    @classmethod
    def detect_and_parse(cls, config_text: str) -> ParseResult:
        """Detect vendor and parse configuration.

        Args:
            config_text: Raw configuration text

        Returns:
            ParseResult with parsed config or errors
        """
        for parser_class in cls._parsers:
            parser = parser_class()
            if parser.detect_vendor(config_text):
                return parser.parse(config_text)

        return ParseResult(
            config=None,
            vendor=None,
            errors=["Could not detect configuration vendor/format"],
            warnings=[],
        )

    @classmethod
    def parse_with_vendor(cls, config_text: str, vendor: Vendor) -> ParseResult:
        """Parse configuration with known vendor.

        Args:
            config_text: Raw configuration text
            vendor: Known vendor type

        Returns:
            ParseResult with parsed config or errors
        """
        parser_map = {
            Vendor.CISCO_IOS: CiscoIOSParser,
            Vendor.CISCO_NXOS: CiscoIOSParser,  # Similar enough for basic parsing
            Vendor.ARISTA_EOS: CiscoIOSParser,  # Arista uses similar syntax
            Vendor.JUNIPER_JUNOS: JuniperJunosParser,
            Vendor.SONIC: SONiCParser,
        }

        parser_class = parser_map.get(vendor)
        if not parser_class:
            return ParseResult(
                config=None,
                vendor=vendor,
                errors=[f"No parser available for vendor: {vendor.value}"],
                warnings=[],
            )

        parser = parser_class()
        result = parser.parse(config_text)
        # Override vendor to the specified one
        if result.config:
            result.config.vendor = vendor
        return result
