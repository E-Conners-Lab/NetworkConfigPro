"""Tests for SONiC configuration generation and parsing."""

import json
import pytest

from src.core.generators.config_generator import ConfigGenerator
from src.core.parsers.config_parser import SONiCParser, ConfigParserFactory
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
    StaticRoute,
    Vendor,
    VLAN,
)


@pytest.fixture
def generator():
    """Create a config generator instance."""
    return ConfigGenerator()


@pytest.fixture
def sonic_parser():
    """Create a SONiC parser instance."""
    return SONiCParser()


@pytest.fixture
def basic_sonic_config():
    """Create a basic SONiC device configuration."""
    return DeviceConfig(
        hostname="sonic-switch",
        vendor=Vendor.SONIC,
        dns_servers=["8.8.8.8", "8.8.4.4"],
        ntp_servers=["pool.ntp.org"],
    )


@pytest.fixture
def sample_sonic_json():
    """Sample SONiC config_db.json configuration."""
    return json.dumps({
        "DEVICE_METADATA": {
            "localhost": {
                "hostname": "sonic-tor-01",
                "bgp_asn": "65100",
                "type": "ToRRouter"
            }
        },
        "PORT": {
            "Ethernet0": {
                "admin_status": "up",
                "description": "Uplink to Spine",
                "mtu": "9100",
                "speed": "100000"
            },
            "Ethernet4": {
                "admin_status": "up",
                "description": "Server Connection"
            },
            "Ethernet8": {
                "admin_status": "down"
            }
        },
        "INTERFACE": {
            "Ethernet0|10.0.0.1/31": {},
            "Ethernet4|10.0.1.1/24": {}
        },
        "LOOPBACK_INTERFACE": {
            "Loopback0|10.1.0.1/32": {}
        },
        "VLAN": {
            "Vlan100": {
                "vlanid": "100"
            },
            "Vlan200": {
                "vlanid": "200"
            }
        },
        "VLAN_MEMBER": {
            "Vlan100|Ethernet8": {
                "tagging_mode": "untagged"
            }
        },
        "VLAN_INTERFACE": {
            "Vlan100|192.168.100.1/24": {}
        },
        "BGP_NEIGHBOR": {
            "10.0.0.0": {
                "rmt_asn": "65200",
                "name": "SPINE-01",
                "local_addr": "10.0.0.1"
            },
            "10.0.0.2": {
                "rmt_asn": "65200",
                "name": "SPINE-02"
            }
        },
        "STATIC_ROUTE": {
            "0.0.0.0/0": {
                "nexthop": "10.0.0.254"
            },
            "192.168.0.0/16": {
                "nexthop": "10.0.1.254",
                "distance": "200"
            }
        },
        "ACL_TABLE": {
            "DATAACL": {
                "type": "L3",
                "policy_desc": "Data ACL"
            }
        },
        "ACL_RULE": {
            "DATAACL|RULE_10": {
                "PRIORITY": "9990",
                "PACKET_ACTION": "DROP",
                "IP_PROTOCOL": "6",
                "SRC_IP": "10.0.0.0/8",
                "L4_DST_PORT": "23"
            },
            "DATAACL|RULE_20": {
                "PRIORITY": "9980",
                "PACKET_ACTION": "FORWARD"
            }
        },
        "NTP_SERVER": {
            "pool.ntp.org": {},
            "time.google.com": {}
        },
        "DNS_NAMESERVER": {
            "8.8.8.8": {},
            "8.8.4.4": {}
        }
    })


class TestSONiCGenerator:
    """Tests for SONiC configuration generation."""

    def test_sonic_in_supported_vendors(self, generator):
        """Test that SONiC is in supported vendors."""
        vendors = generator.get_supported_vendors()
        assert Vendor.SONIC in vendors

    def test_generate_basic_sonic(self, generator, basic_sonic_config):
        """Test generating basic SONiC config."""
        output = generator.generate(basic_sonic_config)

        # Parse the JSON output
        config = json.loads(output)

        assert "DEVICE_METADATA" in config
        assert config["DEVICE_METADATA"]["localhost"]["hostname"] == "sonic-switch"

    def test_generate_sonic_with_interfaces(self, generator, basic_sonic_config):
        """Test generating SONiC config with interfaces."""
        basic_sonic_config.interfaces = [
            Interface(
                name="Ethernet0",
                interface_type=InterfaceType.ETHERNET,
                description="Uplink",
                ip_address="10.0.0.1",
                subnet_mask="255.255.255.254",
                enabled=True,
            ),
            Interface(
                name="Loopback0",
                interface_type=InterfaceType.LOOPBACK,
                ip_address="1.1.1.1",
                subnet_mask="255.255.255.255",
            ),
        ]

        output = generator.generate(basic_sonic_config)
        config = json.loads(output)

        assert "PORT" in config
        assert "Ethernet0" in config["PORT"]
        assert config["PORT"]["Ethernet0"]["admin_status"] == "up"
        assert config["PORT"]["Ethernet0"]["description"] == "Uplink"

        assert "INTERFACE" in config
        assert "Ethernet0|10.0.0.1/31" in config["INTERFACE"]

        assert "LOOPBACK_INTERFACE" in config
        assert "Loopback0|1.1.1.1/32" in config["LOOPBACK_INTERFACE"]

    def test_generate_sonic_with_vlans(self, generator, basic_sonic_config):
        """Test generating SONiC config with VLANs."""
        basic_sonic_config.vlans = [
            VLAN(vlan_id=100, name="SERVERS"),
            VLAN(vlan_id=200, name="MANAGEMENT"),
        ]

        output = generator.generate(basic_sonic_config)
        config = json.loads(output)

        assert "VLAN" in config
        assert "Vlan100" in config["VLAN"]
        assert config["VLAN"]["Vlan100"]["vlanid"] == "100"
        assert "Vlan200" in config["VLAN"]

    def test_generate_sonic_with_bgp(self, generator, basic_sonic_config):
        """Test generating SONiC config with BGP."""
        basic_sonic_config.bgp = BGPConfig(
            local_as=65100,
            router_id="1.1.1.1",
            neighbors=[
                BGPNeighbor(
                    ip_address="10.0.0.2",
                    remote_as=65200,
                    description="SPINE-01",
                ),
            ],
        )

        output = generator.generate(basic_sonic_config)
        config = json.loads(output)

        assert "DEVICE_METADATA" in config
        assert config["DEVICE_METADATA"]["localhost"]["bgp_asn"] == "65100"

        assert "BGP_NEIGHBOR" in config
        assert "10.0.0.2" in config["BGP_NEIGHBOR"]
        assert config["BGP_NEIGHBOR"]["10.0.0.2"]["rmt_asn"] == "65200"
        assert config["BGP_NEIGHBOR"]["10.0.0.2"]["name"] == "SPINE-01"

    def test_generate_sonic_with_static_routes(self, generator, basic_sonic_config):
        """Test generating SONiC config with static routes."""
        basic_sonic_config.static_routes = [
            StaticRoute(
                destination="0.0.0.0",
                mask="0.0.0.0",
                next_hop="10.0.0.254",
            ),
        ]

        output = generator.generate(basic_sonic_config)
        config = json.loads(output)

        assert "STATIC_ROUTE" in config
        assert "0.0.0.0/0" in config["STATIC_ROUTE"]
        assert config["STATIC_ROUTE"]["0.0.0.0/0"]["nexthop"] == "10.0.0.254"

    def test_generate_sonic_with_ntp_dns(self, generator, basic_sonic_config):
        """Test generating SONiC config with NTP and DNS."""
        output = generator.generate(basic_sonic_config)
        config = json.loads(output)

        assert "NTP_SERVER" in config
        assert "pool.ntp.org" in config["NTP_SERVER"]

        assert "DNS_NAMESERVER" in config
        assert "8.8.8.8" in config["DNS_NAMESERVER"]
        assert "8.8.4.4" in config["DNS_NAMESERVER"]


class TestSONiCParser:
    """Tests for SONiC parser."""

    def test_detect_vendor_positive(self, sonic_parser, sample_sonic_json):
        """Test that SONiC config is detected correctly."""
        assert sonic_parser.detect_vendor(sample_sonic_json) is True

    def test_detect_vendor_negative(self, sonic_parser):
        """Test that non-SONiC config is not detected."""
        ios_config = """
hostname router
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
"""
        assert sonic_parser.detect_vendor(ios_config) is False

    def test_detect_vendor_invalid_json(self, sonic_parser):
        """Test that invalid JSON is not detected as SONiC."""
        assert sonic_parser.detect_vendor("not valid json {{{") is False

    def test_parse_hostname(self, sonic_parser, sample_sonic_json):
        """Test hostname parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert result.config is not None
        assert result.config.hostname == "sonic-tor-01"

    def test_parse_interfaces(self, sonic_parser, sample_sonic_json):
        """Test interface parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert len(result.config.interfaces) >= 3

        # Find Ethernet0
        eth0 = next((i for i in result.config.interfaces if i.name == "Ethernet0"), None)
        assert eth0 is not None
        assert eth0.description == "Uplink to Spine"
        assert eth0.ip_address == "10.0.0.1"
        assert eth0.enabled is True
        assert eth0.mtu == 9100

        # Find disabled interface
        eth8 = next((i for i in result.config.interfaces if i.name == "Ethernet8"), None)
        assert eth8 is not None
        assert eth8.enabled is False

    def test_parse_loopback(self, sonic_parser, sample_sonic_json):
        """Test loopback interface parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        lo0 = next((i for i in result.config.interfaces if i.name == "Loopback0"), None)
        assert lo0 is not None
        assert lo0.interface_type == InterfaceType.LOOPBACK
        assert lo0.ip_address == "10.1.0.1"

    def test_parse_vlans(self, sonic_parser, sample_sonic_json):
        """Test VLAN parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert len(result.config.vlans) == 2
        vlan_ids = [v.vlan_id for v in result.config.vlans]
        assert 100 in vlan_ids
        assert 200 in vlan_ids

    def test_parse_vlan_members(self, sonic_parser, sample_sonic_json):
        """Test VLAN member parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        eth8 = next((i for i in result.config.interfaces if i.name == "Ethernet8"), None)
        assert eth8 is not None
        assert eth8.vlan_id == 100

    def test_parse_bgp(self, sonic_parser, sample_sonic_json):
        """Test BGP parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        bgp = result.config.bgp
        assert bgp is not None
        assert bgp.local_as == 65100
        assert len(bgp.neighbors) == 2

        spine1 = next((n for n in bgp.neighbors if n.ip_address == "10.0.0.0"), None)
        assert spine1 is not None
        assert spine1.remote_as == 65200
        assert spine1.description == "SPINE-01"
        assert spine1.update_source == "10.0.0.1"

    def test_parse_static_routes(self, sonic_parser, sample_sonic_json):
        """Test static route parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert len(result.config.static_routes) == 2

        default = next((r for r in result.config.static_routes
                        if r.destination == "0.0.0.0"), None)
        assert default is not None
        assert default.next_hop == "10.0.0.254"

        other = next((r for r in result.config.static_routes
                      if r.destination == "192.168.0.0"), None)
        assert other is not None
        assert other.admin_distance == 200

    def test_parse_acls(self, sonic_parser, sample_sonic_json):
        """Test ACL parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert len(result.config.acls) == 1
        acl = result.config.acls[0]
        assert acl.name == "DATAACL"
        assert len(acl.entries) == 2

        rule10 = next((e for e in acl.entries if e.sequence == 10), None)
        assert rule10 is not None
        assert rule10.action == ACLAction.DENY
        assert rule10.protocol == ACLProtocol.TCP
        assert rule10.destination_port == "23"

    def test_parse_ntp_servers(self, sonic_parser, sample_sonic_json):
        """Test NTP server parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert "pool.ntp.org" in result.config.ntp_servers
        assert "time.google.com" in result.config.ntp_servers

    def test_parse_dns_servers(self, sonic_parser, sample_sonic_json):
        """Test DNS server parsing."""
        result = sonic_parser.parse(sample_sonic_json)

        assert "8.8.8.8" in result.config.dns_servers
        assert "8.8.4.4" in result.config.dns_servers

    def test_parse_result_no_errors(self, sonic_parser, sample_sonic_json):
        """Test that valid config has no parse errors."""
        result = sonic_parser.parse(sample_sonic_json)

        assert len(result.errors) == 0
        assert result.vendor == Vendor.SONIC


class TestSONiCParserFactory:
    """Tests for SONiC auto-detection in ConfigParserFactory."""

    def test_detect_and_parse_sonic(self, sample_sonic_json):
        """Test auto-detection and parsing of SONiC config."""
        result = ConfigParserFactory.detect_and_parse(sample_sonic_json)

        assert result.config is not None
        assert result.vendor == Vendor.SONIC
        assert result.config.hostname == "sonic-tor-01"

    def test_parse_with_known_vendor(self, sample_sonic_json):
        """Test parsing with explicitly specified SONiC vendor."""
        result = ConfigParserFactory.parse_with_vendor(
            sample_sonic_json,
            Vendor.SONIC
        )

        assert result.config is not None
        assert result.config.hostname == "sonic-tor-01"


class TestSONiCFilters:
    """Tests for SONiC-specific Jinja2 filters."""

    def test_sonic_interface_name_gigabit(self, generator):
        """Test converting GigabitEthernet to SONiC format."""
        assert generator._sonic_interface_name("GigabitEthernet0/0") == "Ethernet0"
        assert generator._sonic_interface_name("GigabitEthernet0/1") == "Ethernet1"

    def test_sonic_interface_name_ten_gigabit(self, generator):
        """Test converting TenGigabitEthernet to SONiC format."""
        assert generator._sonic_interface_name("TenGigabitEthernet0/0") == "Ethernet0"

    def test_sonic_interface_name_loopback(self, generator):
        """Test converting Loopback to SONiC format."""
        assert generator._sonic_interface_name("Loopback0") == "Loopback0"
        assert generator._sonic_interface_name("loopback1") == "Loopback1"

    def test_sonic_interface_name_portchannel(self, generator):
        """Test converting Port-Channel to SONiC format."""
        result = generator._sonic_interface_name("Port-Channel1")
        assert result.startswith("PortChannel")

    def test_sonic_interface_name_ethernet_slot_port(self, generator):
        """Test converting Ethernet slot/port notation to SONiC flat numbering."""
        assert generator._sonic_interface_name("Ethernet0/0") == "Ethernet0"
        assert generator._sonic_interface_name("Ethernet0/1") == "Ethernet1"
        assert generator._sonic_interface_name("Ethernet1/0") == "Ethernet48"

    def test_sonic_interface_name_already_sonic(self, generator):
        """Test that SONiC format names are unchanged."""
        assert generator._sonic_interface_name("Ethernet0") == "Ethernet0"
        assert generator._sonic_interface_name("Loopback0") == "Loopback0"
        assert generator._sonic_interface_name("PortChannel0001") == "PortChannel0001"

    def test_sonic_vlan_id(self, generator):
        """Test extracting VLAN ID."""
        assert generator._sonic_vlan_id("Vlan100") == "100"
        assert generator._sonic_vlan_id("vlan200") == "200"
        assert generator._sonic_vlan_id("100") == "100"

    def test_wildcard_to_cidr(self, generator):
        """Test wildcard to CIDR conversion."""
        assert generator._wildcard_to_cidr("0.0.0.0") == 32
        assert generator._wildcard_to_cidr("0.0.0.255") == 24
        assert generator._wildcard_to_cidr("0.0.255.255") == 16
        assert generator._wildcard_to_cidr("0.255.255.255") == 8

    def test_sonic_port_strips_eq(self, generator):
        """Test stripping 'eq' prefix from port numbers for SONiC."""
        assert generator._sonic_port("eq 443") == "443"
        assert generator._sonic_port("eq 22") == "22"
        assert generator._sonic_port("443") == "443"
        assert generator._sonic_port("neq 80") == "80"
        assert generator._sonic_port("lt 1024") == "1024"
        assert generator._sonic_port("gt 1023") == "1023"


class TestSONiCRoundTrip:
    """Test generating and parsing SONiC configs."""

    def test_roundtrip_basic(self, generator, sonic_parser):
        """Test that generated config can be parsed back."""
        original = DeviceConfig(
            hostname="test-switch",
            vendor=Vendor.SONIC,
            interfaces=[
                Interface(
                    name="Ethernet0",
                    interface_type=InterfaceType.ETHERNET,
                    ip_address="10.0.0.1",
                    subnet_mask="255.255.255.254",
                    enabled=True,
                ),
            ],
            dns_servers=["8.8.8.8"],
            ntp_servers=["pool.ntp.org"],
        )

        # Generate
        output = generator.generate(original)

        # Parse back
        result = sonic_parser.parse(output)

        assert result.config is not None
        assert result.config.hostname == "test-switch"
        assert len(result.config.interfaces) >= 1

        eth0 = next((i for i in result.config.interfaces if i.name == "Ethernet0"), None)
        assert eth0 is not None
        assert eth0.ip_address == "10.0.0.1"

    def test_roundtrip_with_bgp(self, generator, sonic_parser):
        """Test roundtrip with BGP configuration."""
        original = DeviceConfig(
            hostname="bgp-switch",
            vendor=Vendor.SONIC,
            bgp=BGPConfig(
                local_as=65100,
                neighbors=[
                    BGPNeighbor(
                        ip_address="10.0.0.2",
                        remote_as=65200,
                        description="SPINE",
                    ),
                ],
            ),
        )

        output = generator.generate(original)
        result = sonic_parser.parse(output)

        assert result.config.bgp is not None
        assert result.config.bgp.local_as == 65100
        assert len(result.config.bgp.neighbors) == 1
        assert result.config.bgp.neighbors[0].remote_as == 65200
