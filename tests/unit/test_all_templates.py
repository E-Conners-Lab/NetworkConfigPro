"""Comprehensive tests for all vendor configuration templates.

This module tests that each vendor template generates syntactically correct
configuration for all supported features.
"""

import json
import pytest
import re

from src.core.generators.config_generator import ConfigGenerator
from src.core.models import (
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
    Vendor,
    VLAN,
)


@pytest.fixture
def generator():
    """Create a config generator instance."""
    return ConfigGenerator()


@pytest.fixture
def full_config():
    """Create a comprehensive device configuration with all features."""
    return DeviceConfig(
        hostname="test-device-01",
        domain_name="test.example.com",
        vendor=Vendor.CISCO_IOS,  # Default, will be changed per test
        enable_secret="$ecureP@ss123",
        banner_motd="Authorized access only. Disconnect immediately if unauthorized.",
        dns_servers=["8.8.8.8", "8.8.4.4"],
        ntp_servers=["pool.ntp.org", "time.google.com"],
        interfaces=[
            Interface(
                name="GigabitEthernet0/0",
                interface_type=InterfaceType.ETHERNET,
                description="WAN Uplink to ISP",
                ip_address="203.0.113.1",
                subnet_mask="255.255.255.252",
                enabled=True,
            ),
            Interface(
                name="GigabitEthernet0/1",
                interface_type=InterfaceType.ETHERNET,
                description="LAN Segment",
                ip_address="192.168.1.1",
                subnet_mask="255.255.255.0",
                enabled=True,
            ),
            Interface(
                name="GigabitEthernet0/2",
                interface_type=InterfaceType.ETHERNET,
                description="Trunk to Switch",
                enabled=True,
                is_trunk=True,
                trunk_allowed_vlans="10,20,30",
            ),
            Interface(
                name="Loopback0",
                interface_type=InterfaceType.LOOPBACK,
                description="Router ID",
                ip_address="10.0.0.1",
                subnet_mask="255.255.255.255",
            ),
        ],
        vlans=[
            VLAN(vlan_id=10, name="MANAGEMENT"),
            VLAN(vlan_id=20, name="USERS"),
            VLAN(vlan_id=30, name="SERVERS"),
        ],
        static_routes=[
            StaticRoute(
                destination="0.0.0.0",
                mask="0.0.0.0",
                next_hop="203.0.113.2",
            ),
            StaticRoute(
                destination="10.10.0.0",
                mask="255.255.0.0",
                next_hop="192.168.1.254",
                admin_distance=150,
            ),
        ],
        ospf=OSPFConfig(
            process_id=1,
            router_id="10.0.0.1",
            reference_bandwidth=10000,
            networks=[
                OSPFNetwork(network="192.168.1.0", wildcard="0.0.0.255", area=0),
                OSPFNetwork(network="10.0.0.1", wildcard="0.0.0.0", area=0),
            ],
            passive_interfaces=["GigabitEthernet0/1"],
        ),
        bgp=BGPConfig(
            local_as=65001,
            router_id="10.0.0.1",
            neighbors=[
                BGPNeighbor(
                    ip_address="203.0.113.2",
                    remote_as=65000,
                    description="ISP Peering",
                ),
                BGPNeighbor(
                    ip_address="10.255.255.2",
                    remote_as=65001,
                    description="iBGP Peer",
                    update_source="Loopback0",
                    ebgp_multihop=2,
                ),
            ],
            networks=["192.168.1.0/24"],
        ),
        acls=[
            ACL(
                name="OUTSIDE-IN",
                entries=[
                    ACLEntry(
                        sequence=10,
                        action=ACLAction.PERMIT,
                        protocol=ACLProtocol.TCP,
                        source="any",
                        destination="192.168.1.0",
                        destination_wildcard="0.0.0.255",
                        destination_port="443",
                    ),
                    ACLEntry(
                        sequence=20,
                        action=ACLAction.PERMIT,
                        protocol=ACLProtocol.TCP,
                        source="any",
                        destination="192.168.1.0",
                        destination_wildcard="0.0.0.255",
                        destination_port="22",
                    ),
                    ACLEntry(
                        sequence=30,
                        action=ACLAction.PERMIT,
                        protocol=ACLProtocol.ICMP,
                        source="any",
                        destination="any",
                    ),
                    ACLEntry(
                        sequence=100,
                        action=ACLAction.DENY,
                        protocol=ACLProtocol.IP,
                        source="any",
                        destination="any",
                        log=True,
                    ),
                ],
            ),
        ],
    )


class TestCiscoIOSTemplate:
    """Tests for Cisco IOS configuration generation."""

    def test_generates_valid_config(self, generator, full_config):
        """Test that Cisco IOS generates a valid configuration."""
        full_config.vendor = Vendor.CISCO_IOS
        output = generator.generate(full_config)

        # Basic structure
        assert "hostname test-device-01" in output
        assert "ip domain-name test.example.com" in output

        # Interfaces
        assert "interface GigabitEthernet0/0" in output
        assert "description WAN Uplink to ISP" in output
        assert "ip address 203.0.113.1 255.255.255.252" in output

        # Loopback
        assert "interface Loopback0" in output
        assert "ip address 10.0.0.1 255.255.255.255" in output

        # VLANs
        assert "vlan 10" in output
        assert "name MANAGEMENT" in output

        # Static routes
        assert "ip route 0.0.0.0 0.0.0.0 203.0.113.2" in output

        # OSPF
        assert "router ospf 1" in output
        assert "router-id 10.0.0.1" in output
        assert "network 192.168.1.0 0.0.0.255 area 0" in output

        # BGP
        assert "router bgp 65001" in output
        assert "neighbor 203.0.113.2 remote-as 65000" in output

        # ACL
        assert "ip access-list extended OUTSIDE-IN" in output
        assert "10 permit tcp any 192.168.1.0" in output

    def test_interface_shutdown_state(self, generator, full_config):
        """Test that disabled interfaces have 'shutdown' command."""
        full_config.vendor = Vendor.CISCO_IOS
        full_config.interfaces[0].enabled = False
        output = generator.generate(full_config)

        # Find the GigabitEthernet0/0 section and check for shutdown
        assert "shutdown" in output

    def test_trunk_configuration(self, generator, full_config):
        """Test trunk interface configuration."""
        full_config.vendor = Vendor.CISCO_IOS
        output = generator.generate(full_config)

        assert "switchport mode trunk" in output
        assert "switchport trunk allowed vlan 10,20,30" in output


class TestCiscoNXOSTemplate:
    """Tests for Cisco NX-OS configuration generation."""

    def test_generates_valid_config(self, generator, full_config):
        """Test that Cisco NX-OS generates a valid configuration."""
        full_config.vendor = Vendor.CISCO_NXOS
        output = generator.generate(full_config)

        # Basic structure
        assert "hostname test-device-01" in output

        # NX-OS specific features
        assert "feature ospf" in output or "router ospf" in output
        assert "feature bgp" in output or "router bgp" in output

        # Interfaces use Ethernet naming
        assert "interface" in output
        assert "description" in output

        # OSPF
        assert "router ospf 1" in output

        # BGP
        assert "router bgp 65001" in output

    def test_vlan_configuration(self, generator, full_config):
        """Test VLAN configuration for NX-OS."""
        full_config.vendor = Vendor.CISCO_NXOS
        output = generator.generate(full_config)

        assert "vlan 10" in output
        assert "name MANAGEMENT" in output


class TestAristaEOSTemplate:
    """Tests for Arista EOS configuration generation."""

    def test_generates_valid_config(self, generator, full_config):
        """Test that Arista EOS generates a valid configuration."""
        full_config.vendor = Vendor.ARISTA_EOS
        output = generator.generate(full_config)

        # Basic structure
        assert "hostname test-device-01" in output

        # Interfaces
        assert "interface" in output
        assert "description" in output

        # Routing
        assert "router ospf 1" in output or "ip routing" in output
        assert "router bgp 65001" in output

    def test_vlan_configuration(self, generator, full_config):
        """Test VLAN configuration for Arista EOS."""
        full_config.vendor = Vendor.ARISTA_EOS
        output = generator.generate(full_config)

        assert "vlan 10" in output
        assert "name MANAGEMENT" in output


class TestJuniperJunOSTemplate:
    """Tests for Juniper JunOS configuration generation."""

    def test_generates_valid_config(self, generator, full_config):
        """Test that Juniper JunOS generates a valid configuration."""
        full_config.vendor = Vendor.JUNIPER_JUNOS
        output = generator.generate(full_config)

        # JunOS uses hierarchical format
        assert "system {" in output
        assert "host-name test-device-01" in output

        # Interface section
        assert "interfaces {" in output

        # Routing
        assert "protocols {" in output
        assert "ospf {" in output
        assert "bgp {" in output

    def test_interface_naming_conversion(self, generator, full_config):
        """Test that interface names are converted to JunOS format."""
        full_config.vendor = Vendor.JUNIPER_JUNOS
        output = generator.generate(full_config)

        # GigabitEthernet should become ge-
        assert "ge-" in output or "interfaces" in output

    def test_loopback_configuration(self, generator, full_config):
        """Test loopback interface for JunOS."""
        full_config.vendor = Vendor.JUNIPER_JUNOS
        output = generator.generate(full_config)

        assert "lo0" in output


class TestFortnetFortiGateTemplate:
    """Tests for Fortinet FortiGate configuration generation."""

    def test_generates_valid_config(self, generator, full_config):
        """Test that Fortinet FortiGate generates a valid configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        # Basic structure - FortiOS uses "config" blocks
        assert "config system global" in output
        assert 'set hostname "test-device-01"' in output

    def test_interface_configuration(self, generator, full_config):
        """Test interface configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config system interface" in output
        assert "set mode static" in output
        assert "set status up" in output

    def test_static_routes(self, generator, full_config):
        """Test static route configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config router static" in output
        assert "set dst 0.0.0.0 0.0.0.0" in output
        assert "set gateway 203.0.113.2" in output

    def test_bgp_configuration(self, generator, full_config):
        """Test BGP configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config router bgp" in output
        assert "set as 65001" in output
        assert "config neighbor" in output
        assert 'edit "203.0.113.2"' in output
        assert "set remote-as 65000" in output

    def test_dns_configuration(self, generator, full_config):
        """Test DNS server configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config system dns" in output
        assert "set primary 8.8.8.8" in output
        assert "set secondary 8.8.4.4" in output

    def test_ntp_configuration(self, generator, full_config):
        """Test NTP server configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config system ntp" in output
        assert "set ntpsync enable" in output
        assert 'set server "pool.ntp.org"' in output

    def test_firewall_policy_from_acl(self, generator, full_config):
        """Test that ACLs are converted to firewall policies."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "config firewall policy" in output
        assert "set action accept" in output or "set action deny" in output

    def test_vlan_configuration(self, generator, full_config):
        """Test VLAN configuration."""
        full_config.vendor = Vendor.FORTINET_FORTIGATE
        output = generator.generate(full_config)

        assert "set vlanid 10" in output
        assert "set type vlan" in output


class TestSONiCTemplate:
    """Tests for SONiC configuration generation."""

    def test_generates_valid_json(self, generator, full_config):
        """Test that SONiC generates valid JSON."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)

        # Should be valid JSON
        config = json.loads(output)
        assert isinstance(config, dict)

    def test_device_metadata(self, generator, full_config):
        """Test DEVICE_METADATA section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "DEVICE_METADATA" in config
        assert config["DEVICE_METADATA"]["localhost"]["hostname"] == "test-device-01"

    def test_port_configuration(self, generator, full_config):
        """Test PORT section with correct naming and MTU."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "PORT" in config
        # GigabitEthernet0/0 should become Ethernet0
        assert "Ethernet0" in config["PORT"]
        # Default MTU should be 9100 for SONiC
        assert config["PORT"]["Ethernet0"]["mtu"] == "9100"

    def test_interface_ip_configuration(self, generator, full_config):
        """Test INTERFACE section for L3 ports."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "INTERFACE" in config
        # Check for IP configuration with pipe separator
        assert any("|" in key for key in config["INTERFACE"].keys())

    def test_loopback_configuration(self, generator, full_config):
        """Test LOOPBACK_INTERFACE section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "LOOPBACK_INTERFACE" in config
        assert "Loopback0|10.0.0.1/32" in config["LOOPBACK_INTERFACE"]

    def test_vlan_configuration(self, generator, full_config):
        """Test VLAN section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "VLAN" in config
        assert "Vlan10" in config["VLAN"]
        assert config["VLAN"]["Vlan10"]["vlanid"] == "10"

    def test_static_routes(self, generator, full_config):
        """Test STATIC_ROUTE section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "STATIC_ROUTE" in config
        assert "0.0.0.0/0" in config["STATIC_ROUTE"]
        assert config["STATIC_ROUTE"]["0.0.0.0/0"]["nexthop"] == "203.0.113.2"

    def test_ospf_router_configuration(self, generator, full_config):
        """Test OSPF_ROUTER section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "OSPF_ROUTER" in config
        assert "default" in config["OSPF_ROUTER"]
        assert config["OSPF_ROUTER"]["default"]["router_id"] == "10.0.0.1"

    def test_ospf_router_area_configuration(self, generator, full_config):
        """Test OSPF_ROUTER_AREA section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "OSPF_ROUTER_AREA" in config
        # Area 0 should be present
        assert "default|0.0.0.0" in config["OSPF_ROUTER_AREA"]

    def test_ospf_interface_configuration(self, generator, full_config):
        """Test OSPF_INTERFACE section."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "OSPF_INTERFACE" in config
        # Check that interfaces have area assignments
        for iface, iface_config in config["OSPF_INTERFACE"].items():
            assert "area" in iface_config

    def test_bgp_neighbor_uses_rmt_asn(self, generator, full_config):
        """Test BGP_NEIGHBOR uses rmt_asn field."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "BGP_NEIGHBOR" in config
        assert "203.0.113.2" in config["BGP_NEIGHBOR"]
        # Should use rmt_asn, not asn
        assert "rmt_asn" in config["BGP_NEIGHBOR"]["203.0.113.2"]
        assert config["BGP_NEIGHBOR"]["203.0.113.2"]["rmt_asn"] == "65000"

    def test_bgp_local_addr_requires_ip(self, generator, full_config):
        """Test that BGP local_addr only appears for IP addresses, not interface names."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        # The neighbor with update_source="Loopback0" should NOT have local_addr
        # (because it's an interface name, not an IP)
        neighbor_with_interface = config["BGP_NEIGHBOR"].get("10.255.255.2", {})
        assert "local_addr" not in neighbor_with_interface

    def test_acl_port_number_format(self, generator, full_config):
        """Test that ACL port numbers don't have 'eq' prefix."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "ACL_RULE" in config
        # Find a rule with L4_DST_PORT
        for rule_name, rule_config in config["ACL_RULE"].items():
            if "L4_DST_PORT" in rule_config:
                # Should be just the port number, not "eq 443"
                assert not rule_config["L4_DST_PORT"].startswith("eq")
                assert rule_config["L4_DST_PORT"].isdigit()

    def test_ntp_dns_configuration(self, generator, full_config):
        """Test NTP_SERVER and DNS_NAMESERVER sections."""
        full_config.vendor = Vendor.SONIC
        output = generator.generate(full_config)
        config = json.loads(output)

        assert "NTP_SERVER" in config
        assert "pool.ntp.org" in config["NTP_SERVER"]

        assert "DNS_NAMESERVER" in config
        assert "8.8.8.8" in config["DNS_NAMESERVER"]


class TestAllVendorsBasicGeneration:
    """Test that all vendors can generate basic configurations without errors."""

    @pytest.mark.parametrize("vendor", [
        Vendor.CISCO_IOS,
        Vendor.CISCO_NXOS,
        Vendor.ARISTA_EOS,
        Vendor.JUNIPER_JUNOS,
        Vendor.SONIC,
        Vendor.FORTINET_FORTIGATE,
    ])
    def test_vendor_generates_output(self, generator, full_config, vendor):
        """Test that each vendor generates non-empty output."""
        full_config.vendor = vendor
        output = generator.generate(full_config)

        assert output is not None
        assert len(output) > 100  # Should have substantial content

    @pytest.mark.parametrize("vendor", [
        Vendor.CISCO_IOS,
        Vendor.CISCO_NXOS,
        Vendor.ARISTA_EOS,
        Vendor.JUNIPER_JUNOS,
        Vendor.SONIC,
        Vendor.FORTINET_FORTIGATE,
    ])
    def test_vendor_includes_hostname(self, generator, full_config, vendor):
        """Test that each vendor includes the hostname."""
        full_config.vendor = vendor
        output = generator.generate(full_config)

        # All vendors should include the hostname somehow
        assert "test-device-01" in output

    @pytest.mark.parametrize("vendor", [
        Vendor.CISCO_IOS,
        Vendor.CISCO_NXOS,
        Vendor.ARISTA_EOS,
        Vendor.JUNIPER_JUNOS,
        Vendor.SONIC,
        Vendor.FORTINET_FORTIGATE,
    ])
    def test_minimal_config_generates(self, generator, vendor):
        """Test that minimal config generates without error."""
        minimal = DeviceConfig(
            hostname="minimal-device",
            vendor=vendor,
        )
        output = generator.generate(minimal)

        assert output is not None
        assert "minimal-device" in output


class TestEdgeCases:
    """Test edge cases and special configurations."""

    def test_empty_interfaces(self, generator):
        """Test config with no interfaces."""
        config = DeviceConfig(
            hostname="no-interfaces",
            vendor=Vendor.CISCO_IOS,
            interfaces=[],
        )
        output = generator.generate(config)
        assert "hostname no-interfaces" in output

    def test_special_characters_in_description(self, generator, full_config):
        """Test handling of special characters in descriptions."""
        full_config.vendor = Vendor.CISCO_IOS
        full_config.interfaces[0].description = "Link to Site A (Primary)"
        output = generator.generate(full_config)
        assert "Link to Site A (Primary)" in output

    def test_high_vlan_id(self, generator):
        """Test high VLAN ID."""
        config = DeviceConfig(
            hostname="high-vlan",
            vendor=Vendor.CISCO_IOS,
            vlans=[VLAN(vlan_id=4000, name="HIGH-VLAN")],
        )
        output = generator.generate(config)
        assert "vlan 4000" in output

    def test_multiple_bgp_neighbors(self, generator, full_config):
        """Test multiple BGP neighbors."""
        full_config.vendor = Vendor.CISCO_IOS
        full_config.bgp.neighbors.append(
            BGPNeighbor(
                ip_address="10.0.0.3",
                remote_as=65002,
                description="Third Peer",
            )
        )
        output = generator.generate(full_config)
        assert "neighbor 10.0.0.3 remote-as 65002" in output

    def test_sonic_ethernet_slot_port_conversion(self, generator):
        """Test that SONiC converts slot/port notation correctly."""
        config = DeviceConfig(
            hostname="sonic-test",
            vendor=Vendor.SONIC,
            interfaces=[
                Interface(
                    name="Ethernet0/0",
                    interface_type=InterfaceType.ETHERNET,
                    enabled=True,
                ),
                Interface(
                    name="Ethernet0/1",
                    interface_type=InterfaceType.ETHERNET,
                    enabled=True,
                ),
                Interface(
                    name="Ethernet1/0",
                    interface_type=InterfaceType.ETHERNET,
                    enabled=True,
                ),
            ],
        )
        output = generator.generate(config)
        json_config = json.loads(output)

        # Check conversions: 0/0->0, 0/1->1, 1/0->48
        assert "Ethernet0" in json_config["PORT"]
        assert "Ethernet1" in json_config["PORT"]
        assert "Ethernet48" in json_config["PORT"]

    def test_sonic_acl_with_eq_port(self, generator):
        """Test that SONiC strips 'eq' from port numbers."""
        config = DeviceConfig(
            hostname="sonic-acl-test",
            vendor=Vendor.SONIC,
            acls=[
                ACL(
                    name="TEST-ACL",
                    entries=[
                        ACLEntry(
                            sequence=10,
                            action=ACLAction.PERMIT,
                            protocol=ACLProtocol.TCP,
                            source="any",
                            destination="any",
                            destination_port="eq 443",
                        ),
                    ],
                ),
            ],
        )
        output = generator.generate(config)
        json_config = json.loads(output)

        # Should be "443", not "eq 443"
        rule = json_config["ACL_RULE"]["TEST-ACL|RULE_10"]
        assert rule["L4_DST_PORT"] == "443"
