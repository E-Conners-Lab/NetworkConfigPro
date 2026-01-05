"""Data models for network configuration elements."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Vendor(Enum):
    """Supported network vendors."""
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    ARISTA_EOS = "arista_eos"
    JUNIPER_JUNOS = "juniper_junos"
    SONIC = "sonic"
    FORTINET_FORTIGATE = "fortinet_fortigate"


class InterfaceType(Enum):
    """Interface types."""
    ETHERNET = "ethernet"
    GIGABIT = "gigabit"
    TEN_GIGABIT = "tengigabit"
    FORTY_GIGABIT = "fortygigabit"
    HUNDRED_GIGABIT = "hundredgigabit"
    LOOPBACK = "loopback"
    VLAN = "vlan"
    PORT_CHANNEL = "port_channel"
    MGMT = "management"


class RoutingProtocol(Enum):
    """Routing protocols."""
    STATIC = "static"
    OSPF = "ospf"
    EIGRP = "eigrp"
    BGP = "bgp"
    ISIS = "isis"


class SwitchportMode(Enum):
    """Switchport modes."""
    ACCESS = "access"
    TRUNK = "trunk"
    DYNAMIC_AUTO = "dynamic auto"
    DYNAMIC_DESIRABLE = "dynamic desirable"


class STPMode(Enum):
    """Spanning Tree Protocol modes."""
    PVST = "pvst"
    RAPID_PVST = "rapid-pvst"
    MST = "mst"


class ACLAction(Enum):
    """ACL actions."""
    PERMIT = "permit"
    DENY = "deny"


class ACLProtocol(Enum):
    """ACL protocols."""
    IP = "ip"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"


@dataclass
class Interface:
    """Network interface configuration."""
    name: str
    interface_type: InterfaceType
    description: str = ""
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    enabled: bool = True
    speed: Optional[str] = None
    duplex: Optional[str] = None
    mtu: int = 1500
    # L2 Switching
    switchport_mode: Optional[SwitchportMode] = None
    access_vlan: Optional[int] = None
    voice_vlan: Optional[int] = None
    trunk_allowed_vlans: Optional[str] = None
    trunk_native_vlan: Optional[int] = None
    # Legacy fields (kept for compatibility)
    vlan_id: Optional[int] = None
    is_trunk: bool = False
    native_vlan: Optional[int] = None
    channel_group: Optional[int] = None
    channel_group_mode: Optional[str] = None  # active, passive, on

    def __post_init__(self):
        """Validate interface configuration."""
        if self.vlan_id is not None and (self.vlan_id < 1 or self.vlan_id > 4094):
            raise ValueError(f"VLAN ID must be between 1 and 4094, got {self.vlan_id}")
        if self.access_vlan is not None and (self.access_vlan < 1 or self.access_vlan > 4094):
            raise ValueError(f"Access VLAN must be between 1 and 4094, got {self.access_vlan}")
        if self.mtu < 64 or self.mtu > 9216:
            raise ValueError(f"MTU must be between 64 and 9216, got {self.mtu}")


@dataclass
class VLAN:
    """VLAN configuration."""
    vlan_id: int
    name: str
    description: str = ""
    state: str = "active"

    def __post_init__(self):
        """Validate VLAN configuration."""
        if self.vlan_id < 1 or self.vlan_id > 4094:
            raise ValueError(f"VLAN ID must be between 1 and 4094, got {self.vlan_id}")
        if not self.name:
            raise ValueError("VLAN name cannot be empty")


@dataclass
class ACLEntry:
    """Single ACL entry/rule."""
    sequence: int
    action: ACLAction
    protocol: ACLProtocol
    source: str
    source_wildcard: str = "0.0.0.0"
    destination: str = "any"
    destination_wildcard: str = "0.0.0.0"
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    log: bool = False
    remark: str = ""


@dataclass
class ACL:
    """Access Control List."""
    name: str
    entries: list[ACLEntry] = field(default_factory=list)
    is_extended: bool = True

    def add_entry(self, entry: ACLEntry) -> None:
        """Add an entry to the ACL."""
        self.entries.append(entry)
        self.entries.sort(key=lambda e: e.sequence)


@dataclass
class StaticRoute:
    """Static route configuration."""
    destination: str
    mask: str
    next_hop: str
    admin_distance: int = 1
    name: str = ""
    permanent: bool = False

    def __post_init__(self):
        """Validate static route."""
        if self.admin_distance < 1 or self.admin_distance > 255:
            raise ValueError(f"Admin distance must be 1-255, got {self.admin_distance}")


@dataclass
class OSPFNetwork:
    """OSPF network statement."""
    network: str
    wildcard: str
    area: int


@dataclass
class OSPFConfig:
    """OSPF configuration."""
    process_id: int
    router_id: Optional[str] = None
    networks: list[OSPFNetwork] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)
    default_information_originate: bool = False
    reference_bandwidth: int = 100

    def __post_init__(self):
        """Validate OSPF configuration."""
        # Allow 0 for vendors like Junos that don't use process IDs
        if self.process_id < 0 or self.process_id > 65535:
            raise ValueError(f"OSPF process ID must be 0-65535, got {self.process_id}")


@dataclass
class BGPNeighbor:
    """BGP neighbor configuration."""
    ip_address: str
    remote_as: int
    description: str = ""
    password: Optional[str] = None
    update_source: Optional[str] = None
    ebgp_multihop: int = 0
    route_map_in: Optional[str] = None
    route_map_out: Optional[str] = None


@dataclass
class BGPConfig:
    """BGP configuration."""
    local_as: int
    router_id: Optional[str] = None
    neighbors: list[BGPNeighbor] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    log_neighbor_changes: bool = True
    redistribute: list[str] = field(default_factory=list)  # ospf, eigrp, static, connected

    def __post_init__(self):
        """Validate BGP configuration."""
        if self.local_as < 1 or self.local_as > 4294967295:
            raise ValueError(f"BGP AS must be 1-4294967295, got {self.local_as}")


@dataclass
class EIGRPNetwork:
    """EIGRP network statement."""
    network: str
    wildcard: Optional[str] = None  # If None, uses classful


@dataclass
class EIGRPConfig:
    """EIGRP configuration."""
    as_number: int
    router_id: Optional[str] = None
    networks: list[EIGRPNetwork] = field(default_factory=list)
    passive_interfaces: list[str] = field(default_factory=list)
    auto_summary: bool = False
    redistribute: list[str] = field(default_factory=list)  # ospf, bgp, static, connected
    named_mode: bool = False  # Use named EIGRP mode
    name: str = "EIGRP_PROCESS"  # For named mode

    def __post_init__(self):
        """Validate EIGRP configuration."""
        if self.as_number < 1 or self.as_number > 65535:
            raise ValueError(f"EIGRP AS must be 1-65535, got {self.as_number}")


@dataclass
class PrefixListEntry:
    """Single prefix-list entry."""
    sequence: int
    action: str  # permit or deny
    prefix: str  # e.g., "10.0.0.0/8"
    ge: Optional[int] = None  # greater than or equal
    le: Optional[int] = None  # less than or equal


@dataclass
class PrefixList:
    """IP prefix-list for route filtering."""
    name: str
    entries: list[PrefixListEntry] = field(default_factory=list)


@dataclass
class RouteMapEntry:
    """Single route-map entry."""
    sequence: int
    action: str  # permit or deny
    match_prefix_list: Optional[str] = None
    match_as_path: Optional[str] = None
    match_community: Optional[str] = None
    set_local_pref: Optional[int] = None
    set_med: Optional[int] = None
    set_as_path_prepend: Optional[str] = None
    set_community: Optional[str] = None
    set_next_hop: Optional[str] = None
    set_weight: Optional[int] = None


@dataclass
class RouteMap:
    """Route-map for policy-based routing and BGP policies."""
    name: str
    entries: list[RouteMapEntry] = field(default_factory=list)


@dataclass
class STPConfig:
    """Spanning Tree Protocol configuration."""
    mode: STPMode = STPMode.RAPID_PVST
    priority: int = 32768  # Default priority
    root_primary_vlans: list[int] = field(default_factory=list)
    root_secondary_vlans: list[int] = field(default_factory=list)
    portfast_default: bool = False
    bpduguard_default: bool = False


@dataclass
class DeviceConfig:
    """Complete device configuration."""
    hostname: str
    vendor: Vendor
    interfaces: list[Interface] = field(default_factory=list)
    vlans: list[VLAN] = field(default_factory=list)
    acls: list[ACL] = field(default_factory=list)
    static_routes: list[StaticRoute] = field(default_factory=list)
    ospf: Optional[OSPFConfig] = None
    eigrp: Optional[EIGRPConfig] = None
    bgp: Optional[BGPConfig] = None
    stp: Optional[STPConfig] = None
    prefix_lists: list[PrefixList] = field(default_factory=list)
    route_maps: list[RouteMap] = field(default_factory=list)
    enable_secret: Optional[str] = None
    domain_name: Optional[str] = None
    dns_servers: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    banner_motd: str = ""
