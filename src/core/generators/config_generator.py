"""Configuration generator using Jinja2 templates."""

import os
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import DeviceConfig, Vendor


class ConfigGenerator:
    """Generates network device configurations from templates."""

    TEMPLATE_MAP = {
        Vendor.CISCO_IOS: "cisco_ios.j2",
        Vendor.CISCO_NXOS: "cisco_nxos.j2",
        Vendor.ARISTA_EOS: "arista_eos.j2",
        Vendor.JUNIPER_JUNOS: "juniper_junos.j2",
        Vendor.SONIC: "sonic.j2",
        Vendor.FORTINET_FORTIGATE: "fortinet_fortigate.j2",
    }

    def __init__(self):
        """Initialize the config generator with Jinja2 environment."""
        template_dir = Path(__file__).parent.parent / "templates" / "vendors"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(default=False),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._register_filters()

    def _register_filters(self) -> None:
        """Register custom Jinja2 filters."""
        self.env.filters["cidr_prefix"] = self._subnet_to_cidr
        self.env.filters["junos_interface_name"] = self._junos_interface_name
        self.env.filters["sonic_interface_name"] = self._sonic_interface_name
        self.env.filters["sonic_vlan_id"] = self._sonic_vlan_id
        self.env.filters["wildcard_to_cidr"] = self._wildcard_to_cidr
        self.env.filters["sonic_port"] = self._sonic_port
        self.env.filters["fortinet_interface_name"] = self._fortinet_interface_name
        self.env.filters["fortinet_parent_interface"] = self._fortinet_parent_interface
        self.env.filters["fortinet_ospf_interface"] = self._fortinet_ospf_interface
        self.env.filters["wildcard_to_netmask"] = self._wildcard_to_netmask

    @staticmethod
    def _subnet_to_cidr(subnet_mask: str) -> int:
        """Convert subnet mask to CIDR prefix length.

        Args:
            subnet_mask: Subnet mask in dotted decimal (e.g., "255.255.255.0")

        Returns:
            CIDR prefix length (e.g., 24)
        """
        if not subnet_mask:
            return 32

        # Handle if already a number
        if isinstance(subnet_mask, int):
            return subnet_mask

        try:
            # Try to parse as dotted decimal
            octets = subnet_mask.split(".")
            if len(octets) == 4:
                binary = "".join(format(int(octet), "08b") for octet in octets)
                return binary.count("1")
        except (ValueError, AttributeError):
            pass

        # If it's already a CIDR number as string
        try:
            return int(subnet_mask)
        except ValueError:
            return 32

    @staticmethod
    def _junos_interface_name(name: str) -> str:
        """Convert interface name to Junos format.

        Args:
            name: Interface name (e.g., "GigabitEthernet0/0")

        Returns:
            Junos-style interface name (e.g., "ge-0/0/0")
        """
        name_lower = name.lower()

        # Common conversions - ordered by specificity (longest patterns first)
        conversions = [
            ("hundredgigabitethernet", "et-"),
            ("fortygigabitethernet", "et-"),
            ("tengigabitethernet", "xe-"),
            ("gigabitethernet", "ge-"),
            ("fastethernet", "fe-"),
            ("ethernet", "et-"),
            ("loopback", "lo"),
            ("port-channel", "ae"),
            ("vlan", "vlan."),
        ]

        for old, new in conversions:
            if old in name_lower:
                # Extract the interface numbers
                remainder = name_lower.replace(old, "").strip()
                # Convert Cisco-style 0/0/0 to Junos-style 0/0/0
                if "/" in remainder:
                    parts = remainder.split("/")
                    if new in ("ge-", "xe-", "fe-", "et-"):
                        return f"{new}{'/'.join(parts)}"
                return f"{new}{remainder}"

        return name

    @staticmethod
    def _sonic_interface_name(name: str) -> str:
        """Convert interface name to SONiC format.

        Args:
            name: Interface name (e.g., "GigabitEthernet0/0", "Ethernet1")

        Returns:
            SONiC-style interface name (e.g., "Ethernet0", "Ethernet1")
        """
        name_lower = name.lower()

        # SONiC uses simple Ethernet numbering
        # Common conversions
        conversions = [
            ("hundredgigabitethernet", "Ethernet"),
            ("fortygigabitethernet", "Ethernet"),
            ("tengigabitethernet", "Ethernet"),
            ("gigabitethernet", "Ethernet"),
            ("fastethernet", "Ethernet"),
            ("ethernet", "Ethernet"),  # Handle Ethernet0/0 -> Ethernet0
            ("loopback", "Loopback"),
            ("port-channel", "PortChannel"),
            ("portchannel", "PortChannel"),
            ("vlan", "Vlan"),
            ("management", "eth"),
            ("mgmt", "eth"),
        ]

        for old, new in conversions:
            if old in name_lower:
                # Extract the interface numbers
                remainder = name_lower.replace(old, "").strip()
                # Convert slot/port format to flat numbering for SONiC
                if "/" in remainder:
                    parts = remainder.split("/")
                    # SONiC typically uses flat numbering: Ethernet0, Ethernet4, etc.
                    # For slot/port, we'll compute: slot * 48 + port (common pattern)
                    try:
                        if len(parts) == 2:
                            flat_num = int(parts[0]) * 48 + int(parts[1])
                        elif len(parts) == 3:
                            flat_num = int(parts[0]) * 48 + int(parts[1]) * 4 + int(parts[2])
                        else:
                            flat_num = int(parts[-1])
                        if new == "PortChannel":
                            return f"{new}{flat_num:04d}"
                        return f"{new}{flat_num}"
                    except ValueError:
                        return f"{new}{remainder.replace('/', '')}"
                else:
                    try:
                        num = int(remainder)
                        if new == "PortChannel":
                            return f"{new}{num:04d}"
                        return f"{new}{num}"
                    except ValueError:
                        return f"{new}{remainder}"

        # Check if it's already in SONiC format
        if name.startswith("Ethernet") or name.startswith("Loopback") or \
           name.startswith("PortChannel") or name.startswith("Vlan"):
            return name

        return name

    @staticmethod
    def _sonic_vlan_id(name: str) -> str:
        """Extract VLAN ID from interface name.

        Args:
            name: VLAN interface name (e.g., "Vlan100", "vlan100", "100")

        Returns:
            VLAN ID as string
        """
        import re
        # Extract numeric portion
        match = re.search(r"(\d+)", str(name))
        if match:
            return match.group(1)
        return name

    @staticmethod
    def _wildcard_to_cidr(wildcard: str) -> int:
        """Convert wildcard mask to CIDR prefix length.

        Args:
            wildcard: Wildcard mask (e.g., "0.0.0.255")

        Returns:
            CIDR prefix length (e.g., 24)
        """
        if not wildcard or wildcard == "0.0.0.0":
            return 32

        try:
            octets = wildcard.split(".")
            if len(octets) == 4:
                # Invert wildcard to get subnet mask
                mask_octets = [255 - int(o) for o in octets]
                binary = "".join(format(octet, "08b") for octet in mask_octets)
                return binary.count("1")
        except (ValueError, AttributeError):
            pass

        return 32

    @staticmethod
    def _sonic_port(port: str) -> str:
        """Strip 'eq ' prefix from port number for SONiC.

        SONiC uses plain port numbers, not 'eq 443' syntax.

        Args:
            port: Port string (e.g., "eq 443" or "443")

        Returns:
            Plain port number (e.g., "443")
        """
        if port:
            port = str(port).strip()
            # Strip common IOS-style prefixes
            for prefix in ["eq ", "neq ", "lt ", "gt ", "range "]:
                if port.lower().startswith(prefix):
                    port = port[len(prefix):].strip()
                    break
        return port

    @staticmethod
    def _fortinet_interface_name(name: str) -> str:
        """Convert interface name to FortiGate format.

        Args:
            name: Interface name (e.g., "GigabitEthernet0/0", "Ethernet1")

        Returns:
            FortiGate-style interface name (e.g., "port1", "wan1")
        """
        name_lower = name.lower()

        # FortiGate uses port1, port2, wan1, wan2, internal, dmz, etc.
        conversions = [
            ("hundredgigabitethernet", "port"),
            ("fortygigabitethernet", "port"),
            ("tengigabitethernet", "port"),
            ("gigabitethernet", "port"),
            ("fastethernet", "port"),
            ("ethernet", "port"),
            ("loopback", "loopback"),
            ("port-channel", "agg"),
            ("portchannel", "agg"),
            ("vlan", "vlan"),
            ("management", "mgmt"),
            ("mgmt", "mgmt"),
        ]

        for old, new in conversions:
            if old in name_lower:
                remainder = name_lower.replace(old, "").strip()
                # Extract numeric portion
                if "/" in remainder:
                    parts = remainder.split("/")
                    try:
                        # FortiGate uses sequential port numbering
                        port_num = int(parts[-1]) + 1  # FortiGate is 1-indexed
                        return f"{new}{port_num}"
                    except ValueError:
                        return f"{new}{remainder.replace('/', '')}"
                else:
                    try:
                        num = int(remainder)
                        if new == "port":
                            return f"{new}{num + 1}"  # FortiGate is 1-indexed
                        return f"{new}{num}"
                    except ValueError:
                        return f"{new}{remainder}"

        # Check if already in FortiGate format
        if name.startswith("port") or name.startswith("wan") or \
           name.startswith("internal") or name.startswith("dmz"):
            return name

        return name

    @staticmethod
    def _fortinet_parent_interface(name: str) -> str:
        """Extract parent interface for VLAN sub-interfaces.

        Args:
            name: Interface name (e.g., "GigabitEthernet0/0.100")

        Returns:
            Parent interface name (e.g., "port1")
        """
        # If it contains a dot, it's a sub-interface
        if "." in name:
            parent = name.split(".")[0]
            return ConfigGenerator._fortinet_interface_name(parent)
        return "internal"  # Default parent interface

    @staticmethod
    def _fortinet_ospf_interface(network: str) -> str:
        """Convert OSPF network to interface name.

        FortiGate OSPF requires interface names, not networks.
        This is a best-effort conversion.

        Args:
            network: Network address (e.g., "10.0.0.0")

        Returns:
            Interface name placeholder
        """
        # This would ideally be mapped from actual interface config
        # For now, return a generic interface
        return "port1"

    @staticmethod
    def _wildcard_to_netmask(wildcard: str) -> str:
        """Convert wildcard mask to subnet mask.

        Args:
            wildcard: Wildcard mask (e.g., "0.0.0.255")

        Returns:
            Subnet mask (e.g., "255.255.255.0")
        """
        if not wildcard or wildcard == "0.0.0.0":
            return "255.255.255.255"

        try:
            octets = wildcard.split(".")
            if len(octets) == 4:
                # Invert wildcard to get subnet mask
                mask_octets = [255 - int(o) for o in octets]
                return ".".join(str(o) for o in mask_octets)
        except (ValueError, AttributeError):
            pass

        return "255.255.255.255"

    def generate(self, config: DeviceConfig) -> str:
        """Generate configuration from a DeviceConfig object.

        Args:
            config: DeviceConfig object with all configuration data

        Returns:
            Generated configuration as a string
        """
        template_name = self.TEMPLATE_MAP.get(config.vendor)
        if not template_name:
            raise ValueError(f"Unsupported vendor: {config.vendor}")

        template = self.env.get_template(template_name)

        # Convert dataclass to dict for template rendering
        config_dict = self._config_to_dict(config)

        return template.render(**config_dict)

    def _config_to_dict(self, config: DeviceConfig) -> dict[str, Any]:
        """Convert DeviceConfig to a dictionary for template rendering.

        Args:
            config: DeviceConfig object

        Returns:
            Dictionary representation suitable for Jinja2
        """
        return {
            "hostname": config.hostname,
            "vendor": config.vendor,
            "interfaces": config.interfaces,
            "vlans": config.vlans,
            "acls": config.acls,
            "static_routes": config.static_routes,
            "ospf": config.ospf,
            "eigrp": config.eigrp,
            "bgp": config.bgp,
            "stp": config.stp,
            "prefix_lists": config.prefix_lists,
            "route_maps": config.route_maps,
            "enable_secret": config.enable_secret,
            "domain_name": config.domain_name,
            "dns_servers": config.dns_servers,
            "ntp_servers": config.ntp_servers,
            "banner_motd": config.banner_motd,
        }

    def get_supported_vendors(self) -> list[Vendor]:
        """Get list of supported vendors.

        Returns:
            List of supported Vendor enum values
        """
        return list(self.TEMPLATE_MAP.keys())

    def generate_from_dict(self, vendor: Vendor, config_dict: dict[str, Any]) -> str:
        """Generate configuration directly from a dictionary.

        Args:
            vendor: Target vendor
            config_dict: Configuration as a dictionary

        Returns:
            Generated configuration as a string
        """
        template_name = self.TEMPLATE_MAP.get(vendor)
        if not template_name:
            raise ValueError(f"Unsupported vendor: {vendor}")

        template = self.env.get_template(template_name)
        return template.render(**config_dict)
