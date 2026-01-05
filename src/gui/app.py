"""Main application window using PySide6."""

import json
import re
import sys
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTabWidget,
    QLabel,
    QLineEdit,
    QTextEdit,
    QPlainTextEdit,
    QPushButton,
    QComboBox,
    QFrame,
    QScrollArea,
    QSplitter,
    QStatusBar,
    QSizePolicy,
    QGroupBox,
    QFileDialog,
    QMessageBox,
    QCheckBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QClipboard, QShortcut, QKeySequence

from .theme import DARK_STYLESHEET, COLORS

from ..core.generators.config_generator import ConfigGenerator
from ..core.models import (
    ACL,
    ACLAction,
    ACLEntry,
    ACLProtocol,
    BGPConfig,
    BGPNeighbor,
    DeviceConfig,
    EIGRPConfig,
    EIGRPNetwork,
    Interface,
    InterfaceType,
    OSPFConfig,
    OSPFNetwork,
    PrefixList,
    PrefixListEntry,
    RouteMap,
    RouteMapEntry,
    STPConfig,
    STPMode,
    SwitchportMode,
    Vendor,
    VLAN,
    StaticRoute,
)
from ..core.validators.config_validator import ConfigValidator
from ..core.parsers.config_parser import ConfigParserFactory
from ..security.vault import SecureVault


class NetConfigProApp(QMainWindow):
    """Main application window for NetConfigPro."""

    VENDOR_DISPLAY = {
        "Cisco IOS/IOS-XE": Vendor.CISCO_IOS,
        "Cisco NX-OS": Vendor.CISCO_NXOS,
        "Arista EOS": Vendor.ARISTA_EOS,
        "Juniper Junos": Vendor.JUNIPER_JUNOS,
        "SONiC": Vendor.SONIC,
        "Fortinet FortiGate": Vendor.FORTINET_FORTIGATE,
    }

    # Interface type options for dropdown
    INTERFACE_TYPE_OPTIONS = [
        "GigabitEthernet",
        "TenGigabitEthernet",
        "FortyGigabitEthernet",
        "HundredGigabitEthernet",
        "Ethernet",
        "Loopback",
        "VLAN",
        "Port-Channel",
        "Management",
    ]

    # Map display names to InterfaceType enum
    INTERFACE_TYPE_MAP = {
        "GigabitEthernet": InterfaceType.GIGABIT,
        "TenGigabitEthernet": InterfaceType.TEN_GIGABIT,
        "FortyGigabitEthernet": InterfaceType.FORTY_GIGABIT,
        "HundredGigabitEthernet": InterfaceType.HUNDRED_GIGABIT,
        "Ethernet": InterfaceType.ETHERNET,
        "Loopback": InterfaceType.LOOPBACK,
        "VLAN": InterfaceType.VLAN,
        "Port-Channel": InterfaceType.PORT_CHANNEL,
        "Management": InterfaceType.MGMT,
    }

    # Interface naming conventions per vendor
    # Configuration templates
    TEMPLATES = {
        "Basic Router": {
            "basic": {
                "vendor": "Cisco IOS/IOS-XE",
                "hostname": "router",
                "domain": "example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8, 8.8.4.4",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "GigabitEthernet", "number": "0/0", "description": "WAN Uplink", "ip": "", "mask": ""},
                {"type": "GigabitEthernet", "number": "0/1", "description": "LAN", "ip": "", "mask": ""},
                {"type": "Loopback", "number": "0", "description": "Router ID", "ip": "", "mask": "255.255.255.255"},
            ],
            "vlans": "",
            "acl": {"name": "", "type": "Extended", "entries": []},
            "static_routes": "",
            "ospf": {"process_id": "1", "router_id": "", "ref_bandwidth": "1000", "networks": "", "passive_interfaces": ""},
            "bgp": {"local_as": "", "router_id": "", "neighbors": [], "networks": ""},
        },
        "L3 Switch": {
            "basic": {
                "vendor": "Cisco IOS/IOS-XE",
                "hostname": "switch",
                "domain": "example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8, 8.8.4.4",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "GigabitEthernet", "number": "0/1", "description": "Uplink to Core", "ip": "", "mask": ""},
                {"type": "VLAN", "number": "10", "description": "Management VLAN", "ip": "", "mask": ""},
                {"type": "VLAN", "number": "20", "description": "Data VLAN", "ip": "", "mask": ""},
                {"type": "VLAN", "number": "30", "description": "Voice VLAN", "ip": "", "mask": ""},
            ],
            "vlans": "10,MANAGEMENT\n20,DATA\n30,VOICE\n99,NATIVE",
            "acl": {"name": "", "type": "Extended", "entries": []},
            "static_routes": "",
            "ospf": {"process_id": "", "router_id": "", "ref_bandwidth": "", "networks": "", "passive_interfaces": ""},
            "bgp": {"local_as": "", "router_id": "", "neighbors": [], "networks": ""},
        },
        "Edge Router with BGP": {
            "basic": {
                "vendor": "Cisco IOS/IOS-XE",
                "hostname": "edge-router",
                "domain": "example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8, 1.1.1.1",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "GigabitEthernet", "number": "0/0", "description": "ISP Uplink", "ip": "", "mask": "255.255.255.252"},
                {"type": "GigabitEthernet", "number": "0/1", "description": "Internal Network", "ip": "", "mask": ""},
                {"type": "Loopback", "number": "0", "description": "Router ID", "ip": "", "mask": "255.255.255.255"},
            ],
            "vlans": "",
            "acl": {
                "name": "INBOUND-FILTER",
                "type": "Extended",
                "entries": [
                    {"seq": "10", "action": "deny", "protocol": "ip", "source": "10.0.0.0", "src_wildcard": "0.255.255.255", "destination": "any", "dst_wildcard": "", "dst_port": "", "log": ""},
                    {"seq": "20", "action": "deny", "protocol": "ip", "source": "172.16.0.0", "src_wildcard": "0.15.255.255", "destination": "any", "dst_wildcard": "", "dst_port": "", "log": ""},
                    {"seq": "30", "action": "deny", "protocol": "ip", "source": "192.168.0.0", "src_wildcard": "0.0.255.255", "destination": "any", "dst_wildcard": "", "dst_port": "", "log": ""},
                    {"seq": "1000", "action": "permit", "protocol": "ip", "source": "any", "src_wildcard": "", "destination": "any", "dst_wildcard": "", "dst_port": "", "log": ""},
                ],
            },
            "static_routes": "",
            "ospf": {"process_id": "1", "router_id": "", "ref_bandwidth": "10000", "networks": "", "passive_interfaces": "GigabitEthernet0/0"},
            "bgp": {"local_as": "65000", "router_id": "", "neighbors": [], "networks": ""},
        },
        "Juniper Edge Router": {
            "basic": {
                "vendor": "Juniper Junos",
                "hostname": "junos-router",
                "domain": "example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8, 8.8.4.4",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "GigabitEthernet", "number": "0/0/0", "description": "WAN Uplink", "ip": "", "mask": "255.255.255.252"},
                {"type": "GigabitEthernet", "number": "0/0/1", "description": "LAN", "ip": "", "mask": ""},
                {"type": "Loopback", "number": "0", "description": "Router ID", "ip": "", "mask": "255.255.255.255"},
            ],
            "vlans": "",
            "acl": {"name": "", "type": "Extended", "entries": []},
            "static_routes": "",
            "ospf": {"process_id": "0", "router_id": "", "ref_bandwidth": "100000", "networks": "", "passive_interfaces": ""},
            "bgp": {"local_as": "65000", "router_id": "", "neighbors": [], "networks": ""},
        },
        "Data Center Spine": {
            "basic": {
                "vendor": "Arista EOS",
                "hostname": "spine",
                "domain": "dc.example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "Ethernet", "number": "1", "description": "Leaf-1", "ip": "", "mask": "255.255.255.252"},
                {"type": "Ethernet", "number": "2", "description": "Leaf-2", "ip": "", "mask": "255.255.255.252"},
                {"type": "Ethernet", "number": "3", "description": "Leaf-3", "ip": "", "mask": "255.255.255.252"},
                {"type": "Ethernet", "number": "4", "description": "Leaf-4", "ip": "", "mask": "255.255.255.252"},
                {"type": "Loopback", "number": "0", "description": "Router ID", "ip": "", "mask": "255.255.255.255"},
            ],
            "vlans": "",
            "acl": {"name": "", "type": "Extended", "entries": []},
            "static_routes": "",
            "ospf": {"process_id": "1", "router_id": "", "ref_bandwidth": "100000", "networks": "", "passive_interfaces": ""},
            "bgp": {"local_as": "65000", "router_id": "", "neighbors": [], "networks": ""},
        },
        "SONiC ToR Switch": {
            "basic": {
                "vendor": "SONiC",
                "hostname": "sonic-tor",
                "domain": "dc.example.com",
                "enable_secret": "",
                "dns_servers": "8.8.8.8, 8.8.4.4",
                "ntp_servers": "pool.ntp.org",
            },
            "interfaces": [
                {"type": "Ethernet", "number": "0", "description": "Uplink-1", "ip": "", "mask": "255.255.255.252"},
                {"type": "Ethernet", "number": "4", "description": "Uplink-2", "ip": "", "mask": "255.255.255.252"},
                {"type": "Ethernet", "number": "8", "description": "Server-1", "ip": "", "mask": ""},
                {"type": "Ethernet", "number": "12", "description": "Server-2", "ip": "", "mask": ""},
                {"type": "Loopback", "number": "0", "description": "Router ID", "ip": "", "mask": "255.255.255.255"},
            ],
            "vlans": "1000,SERVERS\n2000,MANAGEMENT",
            "acl": {"name": "", "type": "Extended", "entries": []},
            "static_routes": "",
            "ospf": {"process_id": "", "router_id": "", "ref_bandwidth": "", "networks": "", "passive_interfaces": ""},
            "bgp": {"local_as": "65100", "router_id": "", "neighbors": [], "networks": ""},
        },
    }

    INTERFACE_PREFIXES = {
        Vendor.CISCO_IOS: {
            "GigabitEthernet": "GigabitEthernet",
            "TenGigabitEthernet": "TenGigabitEthernet",
            "FortyGigabitEthernet": "FortyGigabitEthernet",
            "HundredGigabitEthernet": "HundredGigE",
            "Ethernet": "Ethernet",
            "Loopback": "Loopback",
            "VLAN": "Vlan",
            "Port-Channel": "Port-channel",
            "Management": "Management",
        },
        Vendor.CISCO_NXOS: {
            "GigabitEthernet": "Ethernet",
            "TenGigabitEthernet": "Ethernet",
            "FortyGigabitEthernet": "Ethernet",
            "HundredGigabitEthernet": "Ethernet",
            "Ethernet": "Ethernet",
            "Loopback": "loopback",
            "VLAN": "Vlan",
            "Port-Channel": "port-channel",
            "Management": "mgmt",
        },
        Vendor.ARISTA_EOS: {
            "GigabitEthernet": "Ethernet",
            "TenGigabitEthernet": "Ethernet",
            "FortyGigabitEthernet": "Ethernet",
            "HundredGigabitEthernet": "Ethernet",
            "Ethernet": "Ethernet",
            "Loopback": "Loopback",
            "VLAN": "Vlan",
            "Port-Channel": "Port-Channel",
            "Management": "Management",
        },
        Vendor.JUNIPER_JUNOS: {
            "GigabitEthernet": "ge-",
            "TenGigabitEthernet": "xe-",
            "FortyGigabitEthernet": "et-",
            "HundredGigabitEthernet": "et-",
            "Ethernet": "et-",
            "Loopback": "lo",
            "VLAN": "irb.",
            "Port-Channel": "ae",
            "Management": "em",
        },
        Vendor.SONIC: {
            "GigabitEthernet": "Ethernet",
            "TenGigabitEthernet": "Ethernet",
            "FortyGigabitEthernet": "Ethernet",
            "HundredGigabitEthernet": "Ethernet",
            "Ethernet": "Ethernet",
            "Loopback": "Loopback",
            "VLAN": "Vlan",
            "Port-Channel": "PortChannel",
            "Management": "eth",
        },
        Vendor.FORTINET_FORTIGATE: {
            "GigabitEthernet": "port",
            "TenGigabitEthernet": "port",
            "FortyGigabitEthernet": "port",
            "HundredGigabitEthernet": "port",
            "Ethernet": "port",
            "Loopback": "loopback",
            "VLAN": "vlan",
            "Port-Channel": "agg",
            "Management": "mgmt",
        },
    }

    # Validation patterns
    IP_PATTERN = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    MASK_PATTERN = re.compile(
        r'^(255|254|252|248|240|224|192|128|0)\.'
        r'(255|254|252|248|240|224|192|128|0)\.'
        r'(255|254|252|248|240|224|192|128|0)\.'
        r'(255|254|252|248|240|224|192|128|0)$'
    )
    HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9\-_]{0,62}$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}$')

    # Validation styles
    VALID_STYLE = ""
    INVALID_STYLE = "border: 2px solid #e74c3c; background-color: #3d2020;"
    WARNING_STYLE = "border: 2px solid #f39c12; background-color: #3d3520;"

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NetConfigPro - Network Configuration Generator & Validator")
        self.setMinimumSize(1200, 800)
        self.resize(1400, 900)

        # Initialize backend
        self.generator = ConfigGenerator()
        self.validator = ConfigValidator()
        self.vault = SecureVault()

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create sidebar
        self._create_sidebar(main_layout)

        # Create main content area with tabs
        self._create_main_content(main_layout)

        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        # Setup keyboard shortcuts
        self._setup_shortcuts()

    def _setup_shortcuts(self) -> None:
        """Setup global keyboard shortcuts."""
        # Generate configuration - Ctrl+G
        generate_shortcut = QShortcut(QKeySequence("Ctrl+G"), self)
        generate_shortcut.activated.connect(self._generate_config)

        # Save project - Ctrl+S
        save_shortcut = QShortcut(QKeySequence("Ctrl+S"), self)
        save_shortcut.activated.connect(self._save_project)

        # Load project - Ctrl+O
        load_shortcut = QShortcut(QKeySequence("Ctrl+O"), self)
        load_shortcut.activated.connect(self._load_project)

        # Export configuration - Ctrl+E
        export_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        export_shortcut.activated.connect(self._export_config)

        # Copy output - Ctrl+Shift+C
        copy_shortcut = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        copy_shortcut.activated.connect(self._copy_output)

        # Switch to Generate tab - Ctrl+1
        tab1_shortcut = QShortcut(QKeySequence("Ctrl+1"), self)
        tab1_shortcut.activated.connect(lambda: self._switch_tab(0))

        # Switch to Import tab - Ctrl+2
        tab2_shortcut = QShortcut(QKeySequence("Ctrl+2"), self)
        tab2_shortcut.activated.connect(lambda: self._switch_tab(1))

        # Switch to Diff tab - Ctrl+3
        tab3_shortcut = QShortcut(QKeySequence("Ctrl+3"), self)
        tab3_shortcut.activated.connect(lambda: self._switch_tab(2))

        # Switch to Vault tab - Ctrl+4
        tab4_shortcut = QShortcut(QKeySequence("Ctrl+4"), self)
        tab4_shortcut.activated.connect(lambda: self._switch_tab(3))

        # Switch to Help tab - Ctrl+5
        tab5_shortcut = QShortcut(QKeySequence("Ctrl+5"), self)
        tab5_shortcut.activated.connect(lambda: self._switch_tab(4))

        # Clear form - Ctrl+L
        clear_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        clear_shortcut.activated.connect(self._clear_generate)

        # Add interface - Ctrl+I
        add_iface_shortcut = QShortcut(QKeySequence("Ctrl+I"), self)
        add_iface_shortcut.activated.connect(lambda: self._add_interface_row())

    def _create_sidebar(self, parent_layout: QHBoxLayout) -> None:
        """Create the sidebar navigation."""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet(f"""
            QFrame#sidebar {{
                background-color: {COLORS["surface"]};
                border-right: 1px solid {COLORS["border"]};
            }}
        """)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 20, 12, 20)
        layout.setSpacing(8)

        # Title
        title = QLabel("NetConfigPro")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        layout.addSpacing(20)

        # Navigation buttons
        nav_buttons = [
            ("Generate", 0),
            ("Import", 1),
            ("Diff", 2),
            ("Vault", 3),
            ("Help", 4),
        ]

        self.nav_button_group = []
        for text, index in nav_buttons:
            btn = QPushButton(text)
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setChecked(index == 0)
            btn.clicked.connect(lambda checked, i=index: self._switch_tab(i))
            layout.addWidget(btn)
            self.nav_button_group.append(btn)

        layout.addStretch()

        parent_layout.addWidget(sidebar)

    def _switch_tab(self, index: int) -> None:
        """Switch to a specific tab."""
        self.tabs.setCurrentIndex(index)
        for i, btn in enumerate(self.nav_button_group):
            btn.setChecked(i == index)

    def _create_main_content(self, parent_layout: QHBoxLayout) -> None:
        """Create the main content area with tabs."""
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(16, 16, 16, 16)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Create tabs
        self._create_generate_tab()
        self._create_import_tab()
        self._create_diff_tab()
        self._create_vault_tab()
        self._create_help_tab()

        content_layout.addWidget(self.tabs)
        parent_layout.addWidget(content_widget, 1)

    def _on_tab_changed(self, index: int) -> None:
        """Handle tab change from tab widget."""
        for i, btn in enumerate(self.nav_button_group):
            btn.setChecked(i == index)

    def _create_generate_tab(self) -> None:
        """Create the generate configuration tab."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setSpacing(16)

        # Left side - Input form
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        # Header with vendor selector
        header = QFrame()
        header.setObjectName("card")
        header_layout = QHBoxLayout(header)

        header_label = QLabel("Configuration Settings")
        header_label.setObjectName("heading")
        header_layout.addWidget(header_label)

        header_layout.addStretch()

        # Template selector
        template_label = QLabel("Template:")
        template_label.setObjectName("secondary")
        header_layout.addWidget(template_label)

        self.template_combo = QComboBox()
        self.template_combo.addItem("-- Select Template --")
        self.template_combo.addItems(list(self.TEMPLATES.keys()))
        self.template_combo.currentTextChanged.connect(self._load_template)
        header_layout.addWidget(self.template_combo)

        header_layout.addSpacing(20)

        vendor_label = QLabel("Vendor:")
        vendor_label.setObjectName("secondary")
        header_layout.addWidget(vendor_label)

        self.vendor_combo = QComboBox()
        self.vendor_combo.addItems(list(self.VENDOR_DISPLAY.keys()))
        header_layout.addWidget(self.vendor_combo)

        left_layout.addWidget(header)

        # Scrollable form area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        form_widget = QWidget()
        form_layout = QVBoxLayout(form_widget)
        form_layout.setSpacing(16)

        # Basic Settings group
        basic_group = QGroupBox("Basic Settings")
        basic_layout = QVBoxLayout(basic_group)

        # Hostname
        self.hostname_input = self._create_labeled_input("Hostname", "router1")
        basic_layout.addLayout(self.hostname_input[0])

        # Domain
        self.domain_input = self._create_labeled_input("Domain Name", "example.com")
        basic_layout.addLayout(self.domain_input[0])

        # Enable secret
        self.enable_input = self._create_labeled_input("Enable Secret", "", password=True)
        basic_layout.addLayout(self.enable_input[0])

        # DNS servers
        self.dns_input = self._create_labeled_input("DNS Servers (comma-separated)", "8.8.8.8, 8.8.4.4")
        basic_layout.addLayout(self.dns_input[0])

        # NTP servers
        self.ntp_input = self._create_labeled_input("NTP Servers (comma-separated)", "pool.ntp.org")
        basic_layout.addLayout(self.ntp_input[0])

        form_layout.addWidget(basic_group)

        # Interfaces group
        iface_group = QGroupBox("Interfaces")
        iface_layout = QVBoxLayout(iface_group)

        # Container for interface entries
        self.interfaces_container = QWidget()
        self.interfaces_layout = QVBoxLayout(self.interfaces_container)
        self.interfaces_layout.setContentsMargins(0, 0, 0, 0)
        self.interfaces_layout.setSpacing(8)

        # Store interface rows
        self.interface_rows = []

        # Add initial interface
        self._add_interface_row()

        iface_layout.addWidget(self.interfaces_container)

        # Add/Remove buttons
        iface_btn_layout = QHBoxLayout()
        add_iface_btn = QPushButton("+ Add Interface")
        add_iface_btn.setObjectName("secondary")
        add_iface_btn.clicked.connect(lambda: self._add_interface_row())
        iface_btn_layout.addWidget(add_iface_btn)
        iface_btn_layout.addStretch()
        iface_layout.addLayout(iface_btn_layout)

        form_layout.addWidget(iface_group)

        # VLANs group
        vlan_group = QGroupBox("VLANs (id,name per line)")
        vlan_layout = QVBoxLayout(vlan_group)
        self.vlans_input = QPlainTextEdit()
        self.vlans_input.setPlainText("10,DATA\n20,VOICE")
        self.vlans_input.setMaximumHeight(80)
        vlan_layout.addWidget(self.vlans_input)
        form_layout.addWidget(vlan_group)

        # ACL Configuration group
        acl_group = QGroupBox("Access Control Lists")
        acl_layout = QVBoxLayout(acl_group)

        # ACL name input
        acl_name_row = QHBoxLayout()
        self.acl_name_input = self._create_labeled_input("ACL Name", "BLOCK-TELNET")
        acl_name_row.addLayout(self.acl_name_input[0])

        # ACL type
        acl_type_layout = QVBoxLayout()
        acl_type_layout.setSpacing(4)
        acl_type_label = QLabel("Type")
        acl_type_label.setObjectName("secondary")
        acl_type_layout.addWidget(acl_type_label)
        self.acl_type_combo = QComboBox()
        self.acl_type_combo.addItems(["Extended", "Standard"])
        acl_type_layout.addWidget(self.acl_type_combo)
        acl_name_row.addLayout(acl_type_layout)

        acl_name_row.addStretch()
        acl_layout.addLayout(acl_name_row)

        # ACL entries container
        acl_entries_label = QLabel("ACL Entries")
        acl_entries_label.setObjectName("secondary")
        acl_layout.addWidget(acl_entries_label)

        self.acl_entries_container = QWidget()
        self.acl_entries_layout = QVBoxLayout(self.acl_entries_container)
        self.acl_entries_layout.setContentsMargins(0, 0, 0, 0)
        self.acl_entries_layout.setSpacing(4)
        self.acl_entry_rows = []

        acl_layout.addWidget(self.acl_entries_container)

        # Add ACL entry button
        add_acl_btn = QPushButton("+ Add ACL Entry")
        add_acl_btn.setObjectName("secondary")
        add_acl_btn.clicked.connect(lambda: self._add_acl_entry_row())
        acl_layout.addWidget(add_acl_btn, alignment=Qt.AlignLeft)

        form_layout.addWidget(acl_group)

        # Static Routes group
        routes_group = QGroupBox("Static Routes (dest,mask,nexthop per line)")
        routes_layout = QVBoxLayout(routes_group)
        self.routes_input = QPlainTextEdit()
        self.routes_input.setMaximumHeight(60)
        routes_layout.addWidget(self.routes_input)
        form_layout.addWidget(routes_group)

        # OSPF Configuration group
        ospf_group = QGroupBox("OSPF Configuration")
        ospf_layout = QVBoxLayout(ospf_group)

        # OSPF basic settings row
        ospf_basic_row = QHBoxLayout()

        self.ospf_process_input = self._create_labeled_input("Process ID", "1")
        ospf_basic_row.addLayout(self.ospf_process_input[0])

        self.ospf_router_id_input = self._create_labeled_input("Router ID", "1.1.1.1")
        ospf_basic_row.addLayout(self.ospf_router_id_input[0])

        self.ospf_ref_bw_input = self._create_labeled_input("Ref Bandwidth", "100")
        ospf_basic_row.addLayout(self.ospf_ref_bw_input[0])

        ospf_basic_row.addStretch()
        ospf_layout.addLayout(ospf_basic_row)

        # OSPF networks
        ospf_net_label = QLabel("Networks (network,wildcard,area per line)")
        ospf_net_label.setObjectName("secondary")
        ospf_layout.addWidget(ospf_net_label)

        self.ospf_networks_input = QPlainTextEdit()
        self.ospf_networks_input.setPlaceholderText("10.0.0.0,0.0.0.255,0\n192.168.1.0,0.0.0.255,1")
        self.ospf_networks_input.setMaximumHeight(60)
        ospf_layout.addWidget(self.ospf_networks_input)

        # OSPF passive interfaces
        ospf_passive_label = QLabel("Passive Interfaces (comma-separated)")
        ospf_passive_label.setObjectName("secondary")
        ospf_layout.addWidget(ospf_passive_label)

        self.ospf_passive_input = QLineEdit()
        self.ospf_passive_input.setPlaceholderText("GigabitEthernet0/0, Loopback0")
        ospf_layout.addWidget(self.ospf_passive_input)

        form_layout.addWidget(ospf_group)

        # BGP Configuration group
        bgp_group = QGroupBox("BGP Configuration")
        bgp_layout = QVBoxLayout(bgp_group)

        # BGP basic settings row
        bgp_basic_row = QHBoxLayout()

        self.bgp_as_input = self._create_labeled_input("Local AS", "65000")
        bgp_basic_row.addLayout(self.bgp_as_input[0])

        self.bgp_router_id_input = self._create_labeled_input("Router ID", "1.1.1.1")
        bgp_basic_row.addLayout(self.bgp_router_id_input[0])

        bgp_basic_row.addStretch()
        bgp_layout.addLayout(bgp_basic_row)

        # BGP neighbors section
        bgp_neighbor_label = QLabel("Neighbors")
        bgp_neighbor_label.setObjectName("secondary")
        bgp_layout.addWidget(bgp_neighbor_label)

        # Container for BGP neighbor rows
        self.bgp_neighbors_container = QWidget()
        self.bgp_neighbors_layout = QVBoxLayout(self.bgp_neighbors_container)
        self.bgp_neighbors_layout.setContentsMargins(0, 0, 0, 0)
        self.bgp_neighbors_layout.setSpacing(4)
        self.bgp_neighbor_rows = []

        bgp_layout.addWidget(self.bgp_neighbors_container)

        # Add neighbor button
        add_neighbor_btn = QPushButton("+ Add Neighbor")
        add_neighbor_btn.setObjectName("secondary")
        add_neighbor_btn.clicked.connect(lambda: self._add_bgp_neighbor_row())
        bgp_layout.addWidget(add_neighbor_btn, alignment=Qt.AlignLeft)

        # BGP networks
        bgp_net_label = QLabel("Advertised Networks (one per line, e.g. 10.0.0.0/24)")
        bgp_net_label.setObjectName("secondary")
        bgp_layout.addWidget(bgp_net_label)

        self.bgp_networks_input = QPlainTextEdit()
        self.bgp_networks_input.setPlaceholderText("10.0.0.0/24\n192.168.1.0/24")
        self.bgp_networks_input.setMaximumHeight(50)
        bgp_layout.addWidget(self.bgp_networks_input)

        form_layout.addWidget(bgp_group)

        # === EIGRP Configuration ===
        eigrp_group = QGroupBox("EIGRP Configuration")
        eigrp_layout = QVBoxLayout(eigrp_group)

        eigrp_top_row = QHBoxLayout()

        eigrp_as_layout, self.eigrp_as_input = self._create_labeled_input(
            "AS Number", "100"
        )
        eigrp_top_row.addLayout(eigrp_as_layout)

        eigrp_rid_layout, self.eigrp_router_id_input = self._create_labeled_input(
            "Router ID", "10.0.0.1"
        )
        eigrp_top_row.addLayout(eigrp_rid_layout)

        eigrp_layout.addLayout(eigrp_top_row)

        # Named mode checkbox
        self.eigrp_named_mode = QCheckBox("Use Named EIGRP Mode")
        eigrp_layout.addWidget(self.eigrp_named_mode)

        eigrp_name_layout, self.eigrp_name_input = self._create_labeled_input(
            "EIGRP Process Name (for named mode)", "EIGRP_PROCESS"
        )
        eigrp_layout.addLayout(eigrp_name_layout)

        eigrp_net_label = QLabel("Networks (network,wildcard per line, e.g. 10.0.0.0,0.255.255.255)")
        eigrp_net_label.setObjectName("secondary")
        eigrp_layout.addWidget(eigrp_net_label)

        self.eigrp_networks_input = QPlainTextEdit()
        self.eigrp_networks_input.setPlaceholderText("10.0.0.0,0.255.255.255\n192.168.1.0,0.0.0.255")
        self.eigrp_networks_input.setMaximumHeight(60)
        eigrp_layout.addWidget(self.eigrp_networks_input)

        eigrp_passive_layout, self.eigrp_passive_input = self._create_labeled_input(
            "Passive Interfaces (comma-separated)", "GigabitEthernet0/1, Loopback0"
        )
        eigrp_layout.addLayout(eigrp_passive_layout)

        form_layout.addWidget(eigrp_group)

        # === STP Configuration ===
        stp_group = QGroupBox("Spanning Tree Configuration")
        stp_layout = QVBoxLayout(stp_group)

        stp_top_row = QHBoxLayout()

        stp_mode_container = QVBoxLayout()
        stp_mode_label = QLabel("STP Mode")
        stp_mode_label.setObjectName("secondary")
        stp_mode_container.addWidget(stp_mode_label)
        self.stp_mode_combo = QComboBox()
        self.stp_mode_combo.addItems(["rapid-pvst", "pvst", "mst"])
        stp_mode_container.addWidget(self.stp_mode_combo)
        stp_top_row.addLayout(stp_mode_container)

        stp_priority_layout, self.stp_priority_input = self._create_labeled_input(
            "Bridge Priority", "32768"
        )
        stp_top_row.addLayout(stp_priority_layout)

        stp_layout.addLayout(stp_top_row)

        stp_root_row = QHBoxLayout()
        stp_root_pri_layout, self.stp_root_primary_input = self._create_labeled_input(
            "Root Primary VLANs (comma-separated)", "10, 20, 30"
        )
        stp_root_row.addLayout(stp_root_pri_layout)

        stp_root_sec_layout, self.stp_root_secondary_input = self._create_labeled_input(
            "Root Secondary VLANs (comma-separated)", "40, 50"
        )
        stp_root_row.addLayout(stp_root_sec_layout)
        stp_layout.addLayout(stp_root_row)

        stp_check_row = QHBoxLayout()
        self.stp_portfast_default = QCheckBox("PortFast Default")
        stp_check_row.addWidget(self.stp_portfast_default)
        self.stp_bpduguard_default = QCheckBox("BPDU Guard Default")
        stp_check_row.addWidget(self.stp_bpduguard_default)
        stp_check_row.addStretch()
        stp_layout.addLayout(stp_check_row)

        form_layout.addWidget(stp_group)

        # === Prefix Lists ===
        prefix_group = QGroupBox("Prefix Lists")
        prefix_layout = QVBoxLayout(prefix_group)

        prefix_help = QLabel("Define prefix-lists for route filtering. Use the format shown below.")
        prefix_help.setObjectName("instructions")
        prefix_layout.addWidget(prefix_help)

        # Prefix list entries container
        self.prefix_list_container = QWidget()
        self.prefix_list_layout = QVBoxLayout(self.prefix_list_container)
        self.prefix_list_layout.setContentsMargins(0, 0, 0, 0)
        self.prefix_list_layout.setSpacing(4)
        self.prefix_list_rows = []

        prefix_layout.addWidget(self.prefix_list_container)

        add_prefix_btn = QPushButton("+ Add Prefix List")
        add_prefix_btn.setObjectName("secondary")
        add_prefix_btn.clicked.connect(lambda: self._add_prefix_list_row())
        prefix_layout.addWidget(add_prefix_btn, alignment=Qt.AlignLeft)

        form_layout.addWidget(prefix_group)

        # === Route Maps ===
        routemap_group = QGroupBox("Route Maps")
        routemap_layout = QVBoxLayout(routemap_group)

        routemap_help = QLabel("Define route-maps for BGP policies. Add entries with match/set clauses.")
        routemap_help.setObjectName("instructions")
        routemap_layout.addWidget(routemap_help)

        # Route map entries container
        self.routemap_container = QWidget()
        self.routemap_layout = QVBoxLayout(self.routemap_container)
        self.routemap_layout.setContentsMargins(0, 0, 0, 0)
        self.routemap_layout.setSpacing(4)
        self.routemap_rows = []

        routemap_layout.addWidget(self.routemap_container)

        add_routemap_btn = QPushButton("+ Add Route Map Entry")
        add_routemap_btn.setObjectName("secondary")
        add_routemap_btn.clicked.connect(lambda: self._add_routemap_row())
        routemap_layout.addWidget(add_routemap_btn, alignment=Qt.AlignLeft)

        form_layout.addWidget(routemap_group)

        form_layout.addStretch()
        scroll.setWidget(form_widget)
        left_layout.addWidget(scroll, 1)

        # Buttons
        btn_layout = QHBoxLayout()

        # Left side - Save/Load
        save_btn = QPushButton("Save Project")
        save_btn.setObjectName("secondary")
        save_btn.clicked.connect(self._save_project)
        btn_layout.addWidget(save_btn)

        load_btn = QPushButton("Load Project")
        load_btn.setObjectName("secondary")
        load_btn.clicked.connect(self._load_project)
        btn_layout.addWidget(load_btn)

        btn_layout.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("secondary")
        clear_btn.clicked.connect(self._clear_generate)
        btn_layout.addWidget(clear_btn)

        generate_btn = QPushButton("Generate")
        generate_btn.setObjectName("success")
        generate_btn.clicked.connect(self._generate_config)
        btn_layout.addWidget(generate_btn)

        left_layout.addLayout(btn_layout)

        # Right side - Output
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(16)

        # Output section
        output_group = QGroupBox("Generated Configuration")
        output_layout = QVBoxLayout(output_group)

        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(False)
        output_layout.addWidget(self.output_text)

        output_btn_layout = QHBoxLayout()

        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.setObjectName("secondary")
        copy_btn.clicked.connect(self._copy_output)
        output_btn_layout.addWidget(copy_btn)

        export_btn = QPushButton("Export to File")
        export_btn.setObjectName("secondary")
        export_btn.clicked.connect(self._export_config)
        output_btn_layout.addWidget(export_btn)

        output_btn_layout.addStretch()
        output_layout.addLayout(output_btn_layout)

        right_layout.addWidget(output_group, 2)

        # Validation section
        validation_group = QGroupBox("Validation Results")
        validation_layout = QVBoxLayout(validation_group)
        self.validation_text = QPlainTextEdit()
        self.validation_text.setReadOnly(True)
        validation_layout.addWidget(self.validation_text)
        right_layout.addWidget(validation_group, 1)

        # Add splitter for resizable sections
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([500, 500])

        layout.addWidget(splitter)

        self.tabs.addTab(tab, "Generate")

        # Setup real-time validation for basic fields
        self._setup_basic_validation()

    def _create_labeled_input(self, label: str, placeholder: str, password: bool = False) -> tuple:
        """Create a labeled input field."""
        layout = QVBoxLayout()
        layout.setSpacing(4)

        lbl = QLabel(label)
        lbl.setObjectName("secondary")
        layout.addWidget(lbl)

        entry = QLineEdit()
        entry.setPlaceholderText(placeholder)
        if password:
            entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(entry)

        return (layout, entry)

    def _add_interface_row(self, iface_type: str = "GigabitEthernet", number: str = "0/0",
                           description: str = "", ip: str = "", mask: str = "") -> None:
        """Add a new interface input row."""
        row_widget = QFrame()
        row_widget.setStyleSheet(f"background-color: {COLORS['surface_light']}; border-radius: 4px; padding: 4px;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(8, 8, 8, 8)
        row_layout.setSpacing(8)

        # Helper to create labeled field
        def create_labeled_field(label_text: str, widget: QWidget) -> QVBoxLayout:
            container = QVBoxLayout()
            container.setSpacing(2)
            label = QLabel(label_text)
            label.setObjectName("secondary")
            label.setStyleSheet("font-size: 11px;")
            container.addWidget(label)
            container.addWidget(widget)
            return container

        # Interface type dropdown
        type_combo = QComboBox()
        type_combo.addItems(self.INTERFACE_TYPE_OPTIONS)
        type_combo.setCurrentText(iface_type)
        type_combo.setMinimumWidth(140)
        type_combo.setMaximumWidth(160)
        row_layout.addLayout(create_labeled_field("Type", type_combo))

        # Interface number input
        number_input = QLineEdit()
        number_input.setPlaceholderText("0/0")
        number_input.setText(number)
        number_input.setMinimumWidth(80)
        number_input.setMaximumWidth(150)
        row_layout.addLayout(create_labeled_field("Number", number_input))

        # Description input
        desc_input = QLineEdit()
        desc_input.setPlaceholderText("Uplink to core")
        desc_input.setText(description)
        desc_input.setMinimumWidth(100)
        row_layout.addLayout(create_labeled_field("Description", desc_input))

        # IP address input
        ip_input = QLineEdit()
        ip_input.setPlaceholderText("10.0.0.1")
        ip_input.setText(ip)
        ip_input.setMaximumWidth(120)
        row_layout.addLayout(create_labeled_field("IP Address", ip_input))

        # Subnet mask input
        mask_input = QLineEdit()
        mask_input.setPlaceholderText("255.255.255.0")
        mask_input.setText(mask)
        mask_input.setMaximumWidth(130)
        row_layout.addLayout(create_labeled_field("Subnet Mask", mask_input))

        # Remove button (no label, just spacer alignment)
        remove_container = QVBoxLayout()
        remove_container.setSpacing(2)
        spacer_label = QLabel("")
        spacer_label.setStyleSheet("font-size: 11px;")
        remove_container.addWidget(spacer_label)
        remove_btn = QPushButton("X")
        remove_btn.setMaximumWidth(30)
        remove_btn.setStyleSheet(f"background-color: {COLORS['error']}; padding: 4px 8px;")
        remove_btn.clicked.connect(lambda: self._remove_interface_row(row_widget))
        remove_container.addWidget(remove_btn)
        row_layout.addLayout(remove_container)

        # Store row data
        row_data = {
            "widget": row_widget,
            "type_combo": type_combo,
            "number_input": number_input,
            "desc_input": desc_input,
            "ip_input": ip_input,
            "mask_input": mask_input,
        }
        self.interface_rows.append(row_data)
        self.interfaces_layout.addWidget(row_widget)

        # Setup validation for this row
        self._setup_interface_validation(row_data)

    def _remove_interface_row(self, row_widget: QFrame) -> None:
        """Remove an interface input row."""
        # Find and remove the row data
        for i, row_data in enumerate(self.interface_rows):
            if row_data["widget"] == row_widget:
                self.interface_rows.pop(i)
                break

        # Remove from layout and delete widget
        self.interfaces_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _get_interface_name(self, iface_type: str, number: str, vendor: Vendor) -> str:
        """Build the full interface name based on vendor naming convention."""
        prefix = self.INTERFACE_PREFIXES.get(vendor, {}).get(iface_type, iface_type)
        return f"{prefix}{number}"

    def _add_bgp_neighbor_row(self, ip: str = "", remote_as: str = "", description: str = "") -> None:
        """Add a BGP neighbor input row."""
        row_widget = QFrame()
        row_widget.setStyleSheet(f"background-color: {COLORS['surface_light']}; border-radius: 4px; padding: 4px;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(8, 8, 8, 8)
        row_layout.setSpacing(8)

        # Helper to create labeled field
        def create_labeled_field(label_text: str, widget: QWidget) -> QVBoxLayout:
            container = QVBoxLayout()
            container.setSpacing(2)
            label = QLabel(label_text)
            label.setObjectName("secondary")
            label.setStyleSheet("font-size: 11px;")
            container.addWidget(label)
            container.addWidget(widget)
            return container

        # Neighbor IP
        ip_input = QLineEdit()
        ip_input.setPlaceholderText("10.0.0.2")
        ip_input.setText(ip)
        ip_input.setMinimumWidth(100)
        ip_input.setMaximumWidth(140)
        row_layout.addLayout(create_labeled_field("Neighbor IP", ip_input))

        # Remote AS
        as_input = QLineEdit()
        as_input.setPlaceholderText("65001")
        as_input.setText(remote_as)
        as_input.setMinimumWidth(60)
        as_input.setMaximumWidth(100)
        row_layout.addLayout(create_labeled_field("Remote AS", as_input))

        # Description
        desc_input = QLineEdit()
        desc_input.setPlaceholderText("Peer to ISP")
        desc_input.setText(description)
        desc_input.setMinimumWidth(120)
        row_layout.addLayout(create_labeled_field("Description", desc_input))

        # Update source
        update_src_input = QLineEdit()
        update_src_input.setPlaceholderText("Loopback0")
        update_src_input.setMaximumWidth(120)
        row_layout.addLayout(create_labeled_field("Update Source", update_src_input))

        # eBGP Multihop
        multihop_input = QLineEdit()
        multihop_input.setPlaceholderText("0")
        multihop_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("Multihop", multihop_input))

        # Remove button
        remove_container = QVBoxLayout()
        remove_container.setSpacing(2)
        spacer_label = QLabel("")
        spacer_label.setStyleSheet("font-size: 11px;")
        remove_container.addWidget(spacer_label)
        remove_btn = QPushButton("X")
        remove_btn.setMaximumWidth(30)
        remove_btn.setStyleSheet(f"background-color: {COLORS['error']}; padding: 4px 8px;")
        remove_btn.clicked.connect(lambda: self._remove_bgp_neighbor_row(row_widget))
        remove_container.addWidget(remove_btn)
        row_layout.addLayout(remove_container)

        # Store row data
        row_data = {
            "widget": row_widget,
            "ip_input": ip_input,
            "as_input": as_input,
            "desc_input": desc_input,
            "update_src_input": update_src_input,
            "multihop_input": multihop_input,
        }
        self.bgp_neighbor_rows.append(row_data)
        self.bgp_neighbors_layout.addWidget(row_widget)

        # Setup validation for this row
        self._setup_bgp_neighbor_validation(row_data)

    def _remove_bgp_neighbor_row(self, row_widget: QFrame) -> None:
        """Remove a BGP neighbor input row."""
        for i, row_data in enumerate(self.bgp_neighbor_rows):
            if row_data["widget"] == row_widget:
                self.bgp_neighbor_rows.pop(i)
                break
        self.bgp_neighbors_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _add_prefix_list_row(self, name: str = "", seq: int = 10, action: str = "permit",
                              prefix: str = "", ge: str = "", le: str = "") -> None:
        """Add a prefix-list entry row."""
        row_widget = QFrame()
        row_widget.setStyleSheet(f"background-color: {COLORS['surface_light']}; border-radius: 4px; padding: 4px;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(8, 8, 8, 8)
        row_layout.setSpacing(8)

        def create_labeled_field(label_text: str, widget: QWidget) -> QVBoxLayout:
            container = QVBoxLayout()
            container.setSpacing(2)
            label = QLabel(label_text)
            label.setObjectName("secondary")
            label.setStyleSheet("font-size: 11px;")
            container.addWidget(label)
            container.addWidget(widget)
            return container

        # Prefix list name
        name_input = QLineEdit()
        name_input.setPlaceholderText("ALLOWED-NETWORKS")
        name_input.setText(name)
        name_input.setMinimumWidth(140)
        row_layout.addLayout(create_labeled_field("Name", name_input))

        # Sequence
        seq_input = QLineEdit()
        seq_input.setPlaceholderText("10")
        seq_input.setText(str(seq) if seq else "")
        seq_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("Seq", seq_input))

        # Action
        action_combo = QComboBox()
        action_combo.addItems(["permit", "deny"])
        action_combo.setCurrentText(action)
        action_combo.setMaximumWidth(80)
        row_layout.addLayout(create_labeled_field("Action", action_combo))

        # Prefix (e.g., 10.0.0.0/8)
        prefix_input = QLineEdit()
        prefix_input.setPlaceholderText("10.0.0.0/8")
        prefix_input.setText(prefix)
        prefix_input.setMinimumWidth(120)
        row_layout.addLayout(create_labeled_field("Prefix", prefix_input))

        # ge (greater-equal)
        ge_input = QLineEdit()
        ge_input.setPlaceholderText("16")
        ge_input.setText(ge)
        ge_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("ge", ge_input))

        # le (less-equal)
        le_input = QLineEdit()
        le_input.setPlaceholderText("24")
        le_input.setText(le)
        le_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("le", le_input))

        # Remove button
        remove_container = QVBoxLayout()
        remove_container.setSpacing(2)
        spacer_label = QLabel("")
        spacer_label.setStyleSheet("font-size: 11px;")
        remove_container.addWidget(spacer_label)
        remove_btn = QPushButton("X")
        remove_btn.setMaximumWidth(30)
        remove_btn.setStyleSheet(f"background-color: {COLORS['error']}; padding: 4px 8px;")
        remove_btn.clicked.connect(lambda: self._remove_prefix_list_row(row_widget))
        remove_container.addWidget(remove_btn)
        row_layout.addLayout(remove_container)

        row_data = {
            "widget": row_widget,
            "name_input": name_input,
            "seq_input": seq_input,
            "action_combo": action_combo,
            "prefix_input": prefix_input,
            "ge_input": ge_input,
            "le_input": le_input,
        }
        self.prefix_list_rows.append(row_data)
        self.prefix_list_layout.addWidget(row_widget)

    def _remove_prefix_list_row(self, row_widget: QFrame) -> None:
        """Remove a prefix-list entry row."""
        for i, row_data in enumerate(self.prefix_list_rows):
            if row_data["widget"] == row_widget:
                self.prefix_list_rows.pop(i)
                break
        self.prefix_list_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _add_routemap_row(self, name: str = "", seq: int = 10, action: str = "permit",
                          match_prefix: str = "", set_localpref: str = "",
                          set_med: str = "", set_weight: str = "") -> None:
        """Add a route-map entry row."""
        row_widget = QFrame()
        row_widget.setStyleSheet(f"background-color: {COLORS['surface_light']}; border-radius: 4px; padding: 4px;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(8, 8, 8, 8)
        row_layout.setSpacing(6)

        def create_labeled_field(label_text: str, widget: QWidget) -> QVBoxLayout:
            container = QVBoxLayout()
            container.setSpacing(2)
            label = QLabel(label_text)
            label.setObjectName("secondary")
            label.setStyleSheet("font-size: 11px;")
            container.addWidget(label)
            container.addWidget(widget)
            return container

        # Route map name
        name_input = QLineEdit()
        name_input.setPlaceholderText("TO-PEER")
        name_input.setText(name)
        name_input.setMinimumWidth(100)
        row_layout.addLayout(create_labeled_field("Name", name_input))

        # Sequence
        seq_input = QLineEdit()
        seq_input.setPlaceholderText("10")
        seq_input.setText(str(seq) if seq else "")
        seq_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("Seq", seq_input))

        # Action
        action_combo = QComboBox()
        action_combo.addItems(["permit", "deny"])
        action_combo.setCurrentText(action)
        action_combo.setMaximumWidth(80)
        row_layout.addLayout(create_labeled_field("Action", action_combo))

        # Match prefix-list
        match_prefix_input = QLineEdit()
        match_prefix_input.setPlaceholderText("ALLOWED-NETWORKS")
        match_prefix_input.setText(match_prefix)
        match_prefix_input.setMinimumWidth(120)
        row_layout.addLayout(create_labeled_field("Match Prefix-List", match_prefix_input))

        # Set local-preference
        set_localpref_input = QLineEdit()
        set_localpref_input.setPlaceholderText("200")
        set_localpref_input.setText(set_localpref)
        set_localpref_input.setMaximumWidth(60)
        row_layout.addLayout(create_labeled_field("Set LP", set_localpref_input))

        # Set MED
        set_med_input = QLineEdit()
        set_med_input.setPlaceholderText("100")
        set_med_input.setText(set_med)
        set_med_input.setMaximumWidth(60)
        row_layout.addLayout(create_labeled_field("Set MED", set_med_input))

        # Set weight
        set_weight_input = QLineEdit()
        set_weight_input.setPlaceholderText("1000")
        set_weight_input.setText(set_weight)
        set_weight_input.setMaximumWidth(60)
        row_layout.addLayout(create_labeled_field("Set Weight", set_weight_input))

        # Remove button
        remove_container = QVBoxLayout()
        remove_container.setSpacing(2)
        spacer_label = QLabel("")
        spacer_label.setStyleSheet("font-size: 11px;")
        remove_container.addWidget(spacer_label)
        remove_btn = QPushButton("X")
        remove_btn.setMaximumWidth(30)
        remove_btn.setStyleSheet(f"background-color: {COLORS['error']}; padding: 4px 8px;")
        remove_btn.clicked.connect(lambda: self._remove_routemap_row(row_widget))
        remove_container.addWidget(remove_btn)
        row_layout.addLayout(remove_container)

        row_data = {
            "widget": row_widget,
            "name_input": name_input,
            "seq_input": seq_input,
            "action_combo": action_combo,
            "match_prefix_input": match_prefix_input,
            "set_localpref_input": set_localpref_input,
            "set_med_input": set_med_input,
            "set_weight_input": set_weight_input,
        }
        self.routemap_rows.append(row_data)
        self.routemap_layout.addWidget(row_widget)

    def _remove_routemap_row(self, row_widget: QFrame) -> None:
        """Remove a route-map entry row."""
        for i, row_data in enumerate(self.routemap_rows):
            if row_data["widget"] == row_widget:
                self.routemap_rows.pop(i)
                break
        self.routemap_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _add_acl_entry_row(self, seq: int = 10, action: str = "permit",
                           protocol: str = "ip", source: str = "", dest: str = "") -> None:
        """Add an ACL entry input row."""
        row_widget = QFrame()
        row_widget.setStyleSheet(f"background-color: {COLORS['surface_light']}; border-radius: 4px; padding: 4px;")
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(8, 8, 8, 8)
        row_layout.setSpacing(6)

        # Helper to create labeled field
        def create_labeled_field(label_text: str, widget: QWidget) -> QVBoxLayout:
            container = QVBoxLayout()
            container.setSpacing(2)
            label = QLabel(label_text)
            label.setObjectName("secondary")
            label.setStyleSheet("font-size: 11px;")
            container.addWidget(label)
            container.addWidget(widget)
            return container

        # Sequence number
        seq_input = QLineEdit()
        seq_input.setPlaceholderText("10")
        seq_input.setText(str(seq) if seq else "")
        seq_input.setMaximumWidth(50)
        row_layout.addLayout(create_labeled_field("Seq", seq_input))

        # Action (permit/deny)
        action_combo = QComboBox()
        action_combo.addItems(["permit", "deny"])
        action_combo.setCurrentText(action)
        action_combo.setMaximumWidth(80)
        row_layout.addLayout(create_labeled_field("Action", action_combo))

        # Protocol
        protocol_combo = QComboBox()
        protocol_combo.addItems(["ip", "tcp", "udp", "icmp"])
        protocol_combo.setCurrentText(protocol)
        protocol_combo.setMaximumWidth(70)
        row_layout.addLayout(create_labeled_field("Protocol", protocol_combo))

        # Source
        source_input = QLineEdit()
        source_input.setPlaceholderText("any or 10.0.0.0")
        source_input.setText(source)
        source_input.setMinimumWidth(100)
        row_layout.addLayout(create_labeled_field("Source", source_input))

        # Source wildcard
        src_wc_input = QLineEdit()
        src_wc_input.setPlaceholderText("0.0.0.255")
        src_wc_input.setMaximumWidth(90)
        row_layout.addLayout(create_labeled_field("Src Wildcard", src_wc_input))

        # Destination
        dest_input = QLineEdit()
        dest_input.setPlaceholderText("any or 10.0.0.0")
        dest_input.setText(dest)
        dest_input.setMinimumWidth(100)
        row_layout.addLayout(create_labeled_field("Destination", dest_input))

        # Destination wildcard
        dst_wc_input = QLineEdit()
        dst_wc_input.setPlaceholderText("0.0.0.255")
        dst_wc_input.setMaximumWidth(90)
        row_layout.addLayout(create_labeled_field("Dst Wildcard", dst_wc_input))

        # Destination port (for TCP/UDP)
        dst_port_input = QLineEdit()
        dst_port_input.setPlaceholderText("eq 22")
        dst_port_input.setMaximumWidth(70)
        row_layout.addLayout(create_labeled_field("Dst Port", dst_port_input))

        # Log checkbox replacement - just a simple toggle
        log_combo = QComboBox()
        log_combo.addItems(["", "log"])
        log_combo.setMaximumWidth(55)
        row_layout.addLayout(create_labeled_field("Log", log_combo))

        # Remove button
        remove_container = QVBoxLayout()
        remove_container.setSpacing(2)
        spacer_label = QLabel("")
        spacer_label.setStyleSheet("font-size: 11px;")
        remove_container.addWidget(spacer_label)
        remove_btn = QPushButton("X")
        remove_btn.setMaximumWidth(30)
        remove_btn.setStyleSheet(f"background-color: {COLORS['error']}; padding: 4px 8px;")
        remove_btn.clicked.connect(lambda: self._remove_acl_entry_row(row_widget))
        remove_container.addWidget(remove_btn)
        row_layout.addLayout(remove_container)

        # Store row data
        row_data = {
            "widget": row_widget,
            "seq_input": seq_input,
            "action_combo": action_combo,
            "protocol_combo": protocol_combo,
            "source_input": source_input,
            "src_wc_input": src_wc_input,
            "dest_input": dest_input,
            "dst_wc_input": dst_wc_input,
            "dst_port_input": dst_port_input,
            "log_combo": log_combo,
        }
        self.acl_entry_rows.append(row_data)
        self.acl_entries_layout.addWidget(row_widget)

    def _remove_acl_entry_row(self, row_widget: QFrame) -> None:
        """Remove an ACL entry input row."""
        for i, row_data in enumerate(self.acl_entry_rows):
            if row_data["widget"] == row_widget:
                self.acl_entry_rows.pop(i)
                break
        self.acl_entries_layout.removeWidget(row_widget)
        row_widget.deleteLater()

    def _create_import_tab(self) -> None:
        """Create the import configuration tab."""
        tab = QWidget()
        layout = QHBoxLayout(tab)
        layout.setSpacing(16)

        # Left - Input
        input_group = QGroupBox("Paste Configuration")
        input_layout = QVBoxLayout(input_group)

        self.import_text = QPlainTextEdit()
        input_layout.addWidget(self.import_text)

        btn_layout = QHBoxLayout()

        import_syslog_btn = QPushButton("Import Syslog File")
        import_syslog_btn.setObjectName("secondary")
        import_syslog_btn.clicked.connect(self._import_syslog_file)
        btn_layout.addWidget(import_syslog_btn)

        btn_layout.addStretch()

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("secondary")
        clear_btn.clicked.connect(lambda: self.import_text.clear())
        btn_layout.addWidget(clear_btn)

        parse_btn = QPushButton("Parse Configuration")
        parse_btn.setObjectName("success")
        parse_btn.clicked.connect(self._parse_config)
        btn_layout.addWidget(parse_btn)

        input_layout.addLayout(btn_layout)

        # Right - Results
        results_group = QGroupBox("Parse Results")
        results_layout = QVBoxLayout(results_group)

        self.parse_results_text = QPlainTextEdit()
        self.parse_results_text.setReadOnly(True)
        results_layout.addWidget(self.parse_results_text)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(input_group)
        splitter.addWidget(results_group)
        splitter.setSizes([500, 500])

        layout.addWidget(splitter)

        self.tabs.addTab(tab, "Import")

    def _create_diff_tab(self) -> None:
        """Create the configuration diff tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)

        # Instructions
        instructions = QLabel("Compare two configurations to see the differences. Paste configurations in the left and right panels, then click 'Compare'.")
        instructions.setObjectName("instructions")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)

        # Main content area with two config inputs
        input_area = QWidget()
        input_layout = QHBoxLayout(input_area)
        input_layout.setSpacing(16)

        # Left config
        left_group = QGroupBox("Configuration A (Original)")
        left_layout = QVBoxLayout(left_group)
        self.diff_left_text = QPlainTextEdit()
        self.diff_left_text.setPlaceholderText("Paste first configuration here...")
        left_layout.addWidget(self.diff_left_text)
        input_layout.addWidget(left_group)

        # Right config
        right_group = QGroupBox("Configuration B (New/Modified)")
        right_layout = QVBoxLayout(right_group)
        self.diff_right_text = QPlainTextEdit()
        self.diff_right_text.setPlaceholderText("Paste second configuration here...")
        right_layout.addWidget(self.diff_right_text)
        input_layout.addWidget(right_group)

        layout.addWidget(input_area, 2)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        clear_diff_btn = QPushButton("Clear")
        clear_diff_btn.setObjectName("secondary")
        clear_diff_btn.clicked.connect(self._clear_diff)
        btn_layout.addWidget(clear_diff_btn)

        compare_btn = QPushButton("Compare")
        compare_btn.setObjectName("success")
        compare_btn.clicked.connect(self._compare_configs)
        btn_layout.addWidget(compare_btn)

        layout.addLayout(btn_layout)

        # Diff results
        results_group = QGroupBox("Differences")
        results_layout = QVBoxLayout(results_group)

        self.diff_results_text = QPlainTextEdit()
        self.diff_results_text.setReadOnly(True)
        results_layout.addWidget(self.diff_results_text)

        # Diff stats
        self.diff_stats_label = QLabel("")
        self.diff_stats_label.setObjectName("secondary")
        results_layout.addWidget(self.diff_stats_label)

        layout.addWidget(results_group, 1)

        self.tabs.addTab(tab, "Diff")

    def _clear_diff(self) -> None:
        """Clear the diff inputs and results."""
        self.diff_left_text.clear()
        self.diff_right_text.clear()
        self.diff_results_text.clear()
        self.diff_stats_label.setText("")
        self._show_status("Diff cleared")

    def _compare_configs(self) -> None:
        """Compare the two configurations and display the diff."""
        left_text = self.diff_left_text.toPlainText()
        right_text = self.diff_right_text.toPlainText()

        if not left_text or not right_text:
            self._show_status("Please paste configurations in both panels", error=True)
            return

        left_lines = left_text.splitlines(keepends=True)
        right_lines = right_text.splitlines(keepends=True)

        import difflib

        # Generate unified diff
        diff = list(difflib.unified_diff(
            left_lines,
            right_lines,
            fromfile='Configuration A',
            tofile='Configuration B',
            lineterm=''
        ))

        if not diff:
            self.diff_results_text.setPlainText("Configurations are identical - no differences found.")
            self.diff_stats_label.setText("0 additions, 0 deletions")
            self._show_status("Configurations are identical")
            return

        # Count additions and deletions
        additions = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
        deletions = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))

        # Format the diff output
        diff_output = []
        for line in diff:
            diff_output.append(line.rstrip('\n'))

        self.diff_results_text.setPlainText('\n'.join(diff_output))
        self.diff_stats_label.setText(f"{additions} additions, {deletions} deletions")
        self._show_status(f"Diff complete: {additions} additions, {deletions} deletions")

    def _create_vault_tab(self) -> None:
        """Create the vault tab for secure credential storage."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)

        # Vault status and unlock section
        status_group = QGroupBox("Vault Status")
        status_layout = QVBoxLayout(status_group)

        # Status label
        self.vault_status_label = QLabel()
        self.vault_status_label.setObjectName("heading")
        status_layout.addWidget(self.vault_status_label)

        # Password entry row
        password_row = QHBoxLayout()

        password_label = QLabel("Master Password:")
        password_label.setObjectName("secondary")
        password_row.addWidget(password_label)

        self.vault_password_input = QLineEdit()
        self.vault_password_input.setEchoMode(QLineEdit.Password)
        self.vault_password_input.setMaximumWidth(300)
        self.vault_password_input.returnPressed.connect(self._vault_unlock_or_create)
        password_row.addWidget(self.vault_password_input)

        self.vault_unlock_btn = QPushButton("Unlock")
        self.vault_unlock_btn.setObjectName("success")
        self.vault_unlock_btn.clicked.connect(self._vault_unlock_or_create)
        password_row.addWidget(self.vault_unlock_btn)

        self.vault_lock_btn = QPushButton("Lock")
        self.vault_lock_btn.setObjectName("secondary")
        self.vault_lock_btn.clicked.connect(self._vault_lock)
        password_row.addWidget(self.vault_lock_btn)

        password_row.addStretch()
        status_layout.addLayout(password_row)

        layout.addWidget(status_group)

        # Credentials section
        creds_group = QGroupBox("Stored Credentials")
        creds_layout = QVBoxLayout(creds_group)

        # Credentials list
        self.creds_list = QPlainTextEdit()
        self.creds_list.setReadOnly(True)
        self.creds_list.setMaximumHeight(150)
        creds_layout.addWidget(self.creds_list)

        # Add credential form
        add_cred_row = QHBoxLayout()

        cred_name_layout = QVBoxLayout()
        cred_name_layout.setSpacing(2)
        cred_name_label = QLabel("Name")
        cred_name_label.setObjectName("secondary")
        cred_name_layout.addWidget(cred_name_label)
        self.cred_name_input = QLineEdit()
        self.cred_name_input.setPlaceholderText("router-admin")
        self.cred_name_input.setMaximumWidth(150)
        cred_name_layout.addWidget(self.cred_name_input)
        add_cred_row.addLayout(cred_name_layout)

        cred_user_layout = QVBoxLayout()
        cred_user_layout.setSpacing(2)
        cred_user_label = QLabel("Username")
        cred_user_label.setObjectName("secondary")
        cred_user_layout.addWidget(cred_user_label)
        self.cred_user_input = QLineEdit()
        self.cred_user_input.setPlaceholderText("admin")
        self.cred_user_input.setMaximumWidth(150)
        cred_user_layout.addWidget(self.cred_user_input)
        add_cred_row.addLayout(cred_user_layout)

        cred_pass_layout = QVBoxLayout()
        cred_pass_layout.setSpacing(2)
        cred_pass_label = QLabel("Password")
        cred_pass_label.setObjectName("secondary")
        cred_pass_layout.addWidget(cred_pass_label)
        self.cred_pass_input = QLineEdit()
        self.cred_pass_input.setEchoMode(QLineEdit.Password)
        self.cred_pass_input.setPlaceholderText("password")
        self.cred_pass_input.setMaximumWidth(150)
        cred_pass_layout.addWidget(self.cred_pass_input)
        add_cred_row.addLayout(cred_pass_layout)

        cred_desc_layout = QVBoxLayout()
        cred_desc_layout.setSpacing(2)
        cred_desc_label = QLabel("Description")
        cred_desc_label.setObjectName("secondary")
        cred_desc_layout.addWidget(cred_desc_label)
        self.cred_desc_input = QLineEdit()
        self.cred_desc_input.setPlaceholderText("Core router credentials")
        cred_desc_layout.addWidget(self.cred_desc_input)
        add_cred_row.addLayout(cred_desc_layout)

        add_cred_btn = QPushButton("Add Credential")
        add_cred_btn.setObjectName("success")
        add_cred_btn.clicked.connect(self._vault_add_credential)
        add_cred_row.addWidget(add_cred_btn, alignment=Qt.AlignBottom)

        add_cred_row.addStretch()
        creds_layout.addLayout(add_cred_row)

        # Delete credential row
        del_cred_row = QHBoxLayout()
        del_cred_label = QLabel("Delete credential:")
        del_cred_label.setObjectName("secondary")
        del_cred_row.addWidget(del_cred_label)

        self.del_cred_name_input = QLineEdit()
        self.del_cred_name_input.setPlaceholderText("credential name")
        self.del_cred_name_input.setMaximumWidth(200)
        del_cred_row.addWidget(self.del_cred_name_input)

        del_cred_btn = QPushButton("Delete")
        del_cred_btn.setStyleSheet(f"background-color: {COLORS['error']};")
        del_cred_btn.clicked.connect(self._vault_delete_credential)
        del_cred_row.addWidget(del_cred_btn)

        del_cred_row.addStretch()
        creds_layout.addLayout(del_cred_row)

        layout.addWidget(creds_group)

        # Variables section
        vars_group = QGroupBox("Stored Variables")
        vars_layout = QVBoxLayout(vars_group)

        # Variables list
        self.vars_list = QPlainTextEdit()
        self.vars_list.setReadOnly(True)
        self.vars_list.setMaximumHeight(120)
        vars_layout.addWidget(self.vars_list)

        # Add variable form
        add_var_row = QHBoxLayout()

        var_name_layout = QVBoxLayout()
        var_name_layout.setSpacing(2)
        var_name_label = QLabel("Variable Name")
        var_name_label.setObjectName("secondary")
        var_name_layout.addWidget(var_name_label)
        self.var_name_input = QLineEdit()
        self.var_name_input.setPlaceholderText("SNMP_COMMUNITY")
        self.var_name_input.setMaximumWidth(200)
        var_name_layout.addWidget(self.var_name_input)
        add_var_row.addLayout(var_name_layout)

        var_value_layout = QVBoxLayout()
        var_value_layout.setSpacing(2)
        var_value_label = QLabel("Value")
        var_value_label.setObjectName("secondary")
        var_value_layout.addWidget(var_value_label)
        self.var_value_input = QLineEdit()
        self.var_value_input.setPlaceholderText("public123")
        var_value_layout.addWidget(self.var_value_input)
        add_var_row.addLayout(var_value_layout)

        var_secret_layout = QVBoxLayout()
        var_secret_layout.setSpacing(2)
        var_secret_label = QLabel("Type")
        var_secret_label.setObjectName("secondary")
        var_secret_layout.addWidget(var_secret_label)
        self.var_secret_combo = QComboBox()
        self.var_secret_combo.addItems(["Normal", "Secret"])
        self.var_secret_combo.setMaximumWidth(100)
        var_secret_layout.addWidget(self.var_secret_combo)
        add_var_row.addLayout(var_secret_layout)

        add_var_btn = QPushButton("Add Variable")
        add_var_btn.setObjectName("success")
        add_var_btn.clicked.connect(self._vault_add_variable)
        add_var_row.addWidget(add_var_btn, alignment=Qt.AlignBottom)

        add_var_row.addStretch()
        vars_layout.addLayout(add_var_row)

        layout.addWidget(vars_group)

        layout.addStretch()

        self.tabs.addTab(tab, "Vault")

        # Update vault UI state
        self._update_vault_ui()

    def _update_vault_ui(self) -> None:
        """Update vault UI based on current state."""
        if self.vault.exists:
            if self.vault.is_locked:
                self.vault_status_label.setText("Vault is LOCKED")
                self.vault_unlock_btn.setText("Unlock")
                self.vault_unlock_btn.setEnabled(True)
                self.vault_lock_btn.setEnabled(False)
                self.vault_password_input.setEnabled(True)
                self.creds_list.setPlainText("(Vault is locked)")
                self.vars_list.setPlainText("(Vault is locked)")
            else:
                self.vault_status_label.setText("Vault is UNLOCKED")
                self.vault_unlock_btn.setEnabled(False)
                self.vault_lock_btn.setEnabled(True)
                self.vault_password_input.setEnabled(False)
                self.vault_password_input.clear()
                self._refresh_vault_lists()
        else:
            self.vault_status_label.setText("No vault exists - Enter a password to create one")
            self.vault_unlock_btn.setText("Create Vault")
            self.vault_unlock_btn.setEnabled(True)
            self.vault_lock_btn.setEnabled(False)
            self.vault_password_input.setEnabled(True)
            self.creds_list.setPlainText("(No vault)")
            self.vars_list.setPlainText("(No vault)")

    def _refresh_vault_lists(self) -> None:
        """Refresh credential and variable lists."""
        if self.vault.is_locked:
            return

        # Refresh credentials
        cred_lines = []
        for name in self.vault.list_credentials():
            cred = self.vault.get_credential(name)
            if cred:
                cred_lines.append(f"{name}: {cred['username']} - {cred.get('description', '')}")
        self.creds_list.setPlainText("\n".join(cred_lines) if cred_lines else "(No credentials stored)")

        # Refresh variables
        var_lines = []
        all_vars = self.vault.get_all_variables()
        for name, var in all_vars.items():
            if var.get("is_secret"):
                var_lines.append(f"{name}: ******** (secret)")
            else:
                var_lines.append(f"{name}: {var['value']}")
        self.vars_list.setPlainText("\n".join(var_lines) if var_lines else "(No variables stored)")

    def _vault_unlock_or_create(self) -> None:
        """Unlock or create the vault."""
        password = self.vault_password_input.text()
        if not password:
            self._show_status("Please enter a master password", error=True)
            return

        try:
            if self.vault.exists:
                self.vault.unlock(password)
                self._show_status("Vault unlocked successfully")
            else:
                self.vault.create(password)
                self._show_status("Vault created successfully")
            self._update_vault_ui()
        except ValueError as e:
            QMessageBox.warning(self, "Vault Error", str(e))
            self._show_status(f"Vault error: {e}", error=True)

    def _vault_lock(self) -> None:
        """Lock the vault."""
        self.vault.lock()
        self._update_vault_ui()
        self._show_status("Vault locked")

    def _vault_add_credential(self) -> None:
        """Add a credential to the vault."""
        if self.vault.is_locked:
            self._show_status("Vault is locked", error=True)
            return

        name = self.cred_name_input.text().strip()
        username = self.cred_user_input.text().strip()
        password = self.cred_pass_input.text()
        description = self.cred_desc_input.text().strip()

        if not name or not username or not password:
            self._show_status("Name, username, and password are required", error=True)
            return

        try:
            self.vault.store_credential(name, username, password, description)
            self._show_status(f"Credential '{name}' stored")
            self.cred_name_input.clear()
            self.cred_user_input.clear()
            self.cred_pass_input.clear()
            self.cred_desc_input.clear()
            self._refresh_vault_lists()
        except Exception as e:
            self._show_status(f"Failed to store credential: {e}", error=True)

    def _vault_delete_credential(self) -> None:
        """Delete a credential from the vault."""
        if self.vault.is_locked:
            self._show_status("Vault is locked", error=True)
            return

        name = self.del_cred_name_input.text().strip()
        if not name:
            self._show_status("Enter credential name to delete", error=True)
            return

        if self.vault.delete_credential(name):
            self._show_status(f"Credential '{name}' deleted")
            self.del_cred_name_input.clear()
            self._refresh_vault_lists()
        else:
            self._show_status(f"Credential '{name}' not found", error=True)

    def _vault_add_variable(self) -> None:
        """Add a variable to the vault."""
        if self.vault.is_locked:
            self._show_status("Vault is locked", error=True)
            return

        name = self.var_name_input.text().strip()
        value = self.var_value_input.text()
        is_secret = self.var_secret_combo.currentText() == "Secret"

        if not name or not value:
            self._show_status("Variable name and value are required", error=True)
            return

        try:
            self.vault.store_variable(name, value, is_secret)
            self._show_status(f"Variable '{name}' stored")
            self.var_name_input.clear()
            self.var_value_input.clear()
            self.var_secret_combo.setCurrentIndex(0)
            self._refresh_vault_lists()
        except Exception as e:
            self._show_status(f"Failed to store variable: {e}", error=True)

    def _create_help_tab(self) -> None:
        """Create the help tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        help_group = QGroupBox("Help & Documentation")
        help_layout = QVBoxLayout(help_group)

        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml("""
        <h2>NetConfigPro - Help</h2>
        <p>Welcome to NetConfigPro! This tool helps network engineers generate and validate
        network device configurations for labs, production, and certification study.</p>

        <h3>Generate Tab</h3>
        <ol>
            <li>Select your target vendor (Cisco IOS, NX-OS, Arista, Juniper)</li>
            <li>Fill in the configuration fields</li>
            <li>Click "Generate" to create the configuration</li>
            <li>Review validation results for errors and warnings</li>
            <li>Click "Copy to Clipboard" or "Export to File"</li>
        </ol>

        <h3>Supported Features</h3>

        <h4>Layer 2 Switching</h4>
        <ul>
            <li><b>Switchport Modes:</b> Access, Trunk, Dynamic</li>
            <li><b>Access VLAN:</b> Assign port to a VLAN</li>
            <li><b>Voice VLAN:</b> For IP phones (data + voice on same port)</li>
            <li><b>Trunk Config:</b> Native VLAN, allowed VLANs</li>
        </ul>

        <h4>Spanning Tree Protocol (STP)</h4>
        <ul>
            <li><b>Modes:</b> PVST, Rapid-PVST (recommended), MST</li>
            <li><b>Bridge Priority:</b> Set priority for root bridge election</li>
            <li><b>Root Primary/Secondary:</b> Per-VLAN root configuration</li>
            <li><b>PortFast:</b> Fast convergence for access ports</li>
            <li><b>BPDU Guard:</b> Protect against unauthorized switches</li>
        </ul>

        <h4>Routing Protocols</h4>
        <ul>
            <li><b>Static Routes:</b> destination, mask, next-hop</li>
            <li><b>OSPF:</b> Process ID, router-id, networks, passive interfaces, reference bandwidth</li>
            <li><b>EIGRP:</b> Classic mode or Named mode, AS number, networks, passive interfaces</li>
            <li><b>BGP:</b> Local AS, router-id, neighbors with authentication, route-maps</li>
        </ul>

        <h4>BGP Policy (Prefix Lists & Route Maps)</h4>
        <ul>
            <li><b>Prefix Lists:</b> Filter routes by prefix with ge/le modifiers</li>
            <li><b>Route Maps:</b> Match conditions and set attributes</li>
            <li><b>Set Clauses:</b> local-preference, MED, weight, as-path prepend</li>
        </ul>

        <h3>Interface Naming</h3>
        <p>Interface names are automatically generated based on the selected vendor:</p>
        <ul>
            <li><b>Cisco IOS:</b> GigabitEthernet0/0, TenGigabitEthernet1/0, Loopback0</li>
            <li><b>Cisco NX-OS:</b> Ethernet1/1, loopback0, port-channel1</li>
            <li><b>Arista EOS:</b> Ethernet1, Loopback0, Port-Channel1</li>
            <li><b>Juniper Junos:</b> ge-0/0/0, xe-0/0/0, lo0, ae0</li>
        </ul>

        <h3>Other Tabs</h3>
        <ul>
            <li><b>Import:</b> Paste and parse existing device configurations</li>
            <li><b>Diff:</b> Compare two configurations side-by-side</li>
            <li><b>Vault:</b> Securely store credentials and variables (AES-256 encrypted)</li>
        </ul>

        <h3>Keyboard Shortcuts</h3>
        <table border="0" cellpadding="4">
            <tr><td><b>Ctrl+G</b></td><td>Generate configuration</td></tr>
            <tr><td><b>Ctrl+S</b></td><td>Save project</td></tr>
            <tr><td><b>Ctrl+O</b></td><td>Open/Load project</td></tr>
            <tr><td><b>Ctrl+E</b></td><td>Export configuration to file</td></tr>
            <tr><td><b>Ctrl+Shift+C</b></td><td>Copy output to clipboard</td></tr>
            <tr><td><b>Ctrl+L</b></td><td>Clear form</td></tr>
            <tr><td><b>Ctrl+I</b></td><td>Add interface row</td></tr>
            <tr><td><b>Ctrl+1-5</b></td><td>Switch between tabs</td></tr>
        </table>

        <h3>Best Practices</h3>
        <ul>
            <li>Always add descriptions to interfaces</li>
            <li>Configure router-id for OSPF, EIGRP, and BGP</li>
            <li>Enable PortFast and BPDU Guard on access ports</li>
            <li>Use prefix-lists for granular BGP route filtering</li>
            <li>Use strong passwords (not "cisco" or "admin")</li>
            <li>Review validation warnings before deploying</li>
        </ul>
        """)
        help_layout.addWidget(help_text)

        layout.addWidget(help_group)

        self.tabs.addTab(tab, "Help")

    def _generate_config(self) -> None:
        """Generate configuration from form inputs."""
        try:
            vendor_name = self.vendor_combo.currentText()
            vendor = self.VENDOR_DISPLAY.get(vendor_name)

            hostname = self.hostname_input[1].text().strip()
            if not hostname:
                self._show_status("Hostname is required", error=True)
                return

            # Build config
            config = DeviceConfig(
                hostname=hostname,
                vendor=vendor,
                domain_name=self.domain_input[1].text().strip() or None,
                enable_secret=self.enable_input[1].text() or None,
            )

            # DNS servers
            dns = self.dns_input[1].text().strip()
            if dns:
                config.dns_servers = [s.strip() for s in dns.split(",") if s.strip()]

            # NTP servers
            ntp = self.ntp_input[1].text().strip()
            if ntp:
                config.ntp_servers = [s.strip() for s in ntp.split(",") if s.strip()]

            # Interfaces - build from structured inputs
            for row_data in self.interface_rows:
                iface_type = row_data["type_combo"].currentText()
                number = row_data["number_input"].text().strip()
                description = row_data["desc_input"].text().strip()
                ip_address = row_data["ip_input"].text().strip() or None
                subnet_mask = row_data["mask_input"].text().strip() or None

                if number:  # Only add if number is provided
                    # Build the full interface name based on vendor
                    full_name = self._get_interface_name(iface_type, number, vendor)
                    interface_type_enum = self.INTERFACE_TYPE_MAP.get(iface_type, InterfaceType.GIGABIT)

                    iface = Interface(
                        name=full_name,
                        interface_type=interface_type_enum,
                        description=description,
                        ip_address=ip_address,
                        subnet_mask=subnet_mask,
                    )
                    config.interfaces.append(iface)

            # VLANs
            vlan_text = self.vlans_input.toPlainText().strip()
            for line in vlan_text.split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 2:
                    try:
                        config.vlans.append(VLAN(
                            vlan_id=int(parts[0]),
                            name=parts[1],
                        ))
                    except ValueError:
                        pass

            # ACLs
            acl_name = self.acl_name_input[1].text().strip()
            if acl_name and self.acl_entry_rows:
                is_extended = self.acl_type_combo.currentText() == "Extended"
                acl = ACL(name=acl_name, is_extended=is_extended)

                for row_data in self.acl_entry_rows:
                    seq_text = row_data["seq_input"].text().strip()
                    source = row_data["source_input"].text().strip()

                    if seq_text and source:
                        try:
                            action_str = row_data["action_combo"].currentText()
                            action = ACLAction.PERMIT if action_str == "permit" else ACLAction.DENY

                            protocol_str = row_data["protocol_combo"].currentText()
                            protocol_map = {
                                "ip": ACLProtocol.IP,
                                "tcp": ACLProtocol.TCP,
                                "udp": ACLProtocol.UDP,
                                "icmp": ACLProtocol.ICMP,
                            }
                            protocol = protocol_map.get(protocol_str, ACLProtocol.IP)

                            entry = ACLEntry(
                                sequence=int(seq_text),
                                action=action,
                                protocol=protocol,
                                source=source,
                                source_wildcard=row_data["src_wc_input"].text().strip() or "0.0.0.0",
                                destination=row_data["dest_input"].text().strip() or "any",
                                destination_wildcard=row_data["dst_wc_input"].text().strip() or "0.0.0.0",
                                destination_port=row_data["dst_port_input"].text().strip() or None,
                                log=row_data["log_combo"].currentText() == "log",
                            )
                            acl.add_entry(entry)
                        except ValueError:
                            pass

                if acl.entries:
                    config.acls.append(acl)

            # Static routes
            route_text = self.routes_input.toPlainText().strip()
            for line in route_text.split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3:
                    config.static_routes.append(StaticRoute(
                        destination=parts[0],
                        mask=parts[1],
                        next_hop=parts[2],
                    ))

            # OSPF
            ospf_process = self.ospf_process_input[1].text().strip()
            if ospf_process:
                try:
                    ospf = OSPFConfig(
                        process_id=int(ospf_process),
                        router_id=self.ospf_router_id_input[1].text().strip() or None,
                    )

                    # Reference bandwidth
                    ref_bw = self.ospf_ref_bw_input[1].text().strip()
                    if ref_bw:
                        try:
                            ospf.reference_bandwidth = int(ref_bw)
                        except ValueError:
                            pass

                    # OSPF networks
                    ospf_net_text = self.ospf_networks_input.toPlainText().strip()
                    for line in ospf_net_text.split("\n"):
                        parts = [p.strip() for p in line.split(",")]
                        if len(parts) >= 3:
                            try:
                                ospf.networks.append(OSPFNetwork(
                                    network=parts[0],
                                    wildcard=parts[1],
                                    area=int(parts[2]),
                                ))
                            except ValueError:
                                pass

                    # Passive interfaces
                    passive_text = self.ospf_passive_input.text().strip()
                    if passive_text:
                        ospf.passive_interfaces = [i.strip() for i in passive_text.split(",") if i.strip()]

                    config.ospf = ospf
                except ValueError:
                    pass

            # BGP
            bgp_as = self.bgp_as_input[1].text().strip()
            if bgp_as:
                try:
                    bgp = BGPConfig(
                        local_as=int(bgp_as),
                        router_id=self.bgp_router_id_input[1].text().strip() or None,
                    )

                    # BGP neighbors
                    for row_data in self.bgp_neighbor_rows:
                        neighbor_ip = row_data["ip_input"].text().strip()
                        remote_as = row_data["as_input"].text().strip()
                        if neighbor_ip and remote_as:
                            try:
                                neighbor = BGPNeighbor(
                                    ip_address=neighbor_ip,
                                    remote_as=int(remote_as),
                                    description=row_data["desc_input"].text().strip(),
                                    update_source=row_data["update_src_input"].text().strip() or None,
                                )
                                multihop = row_data["multihop_input"].text().strip()
                                if multihop:
                                    try:
                                        neighbor.ebgp_multihop = int(multihop)
                                    except ValueError:
                                        pass
                                bgp.neighbors.append(neighbor)
                            except ValueError:
                                pass

                    # BGP networks
                    bgp_net_text = self.bgp_networks_input.toPlainText().strip()
                    for line in bgp_net_text.split("\n"):
                        network = line.strip()
                        if network:
                            bgp.networks.append(network)

                    config.bgp = bgp
                except ValueError:
                    pass

            # EIGRP
            eigrp_as = self.eigrp_as_input.text().strip()
            if eigrp_as:
                try:
                    eigrp = EIGRPConfig(
                        as_number=int(eigrp_as),
                        router_id=self.eigrp_router_id_input.text().strip() or None,
                        named_mode=self.eigrp_named_mode.isChecked(),
                        name=self.eigrp_name_input.text().strip() or "EIGRP_PROCESS",
                    )

                    # EIGRP networks
                    eigrp_net_text = self.eigrp_networks_input.toPlainText().strip()
                    for line in eigrp_net_text.split("\n"):
                        parts = [p.strip() for p in line.split(",")]
                        if parts and parts[0]:
                            network = parts[0]
                            wildcard = parts[1] if len(parts) > 1 else None
                            eigrp.networks.append(EIGRPNetwork(
                                network=network,
                                wildcard=wildcard,
                            ))

                    # Passive interfaces
                    passive_text = self.eigrp_passive_input.text().strip()
                    if passive_text:
                        eigrp.passive_interfaces = [i.strip() for i in passive_text.split(",") if i.strip()]

                    config.eigrp = eigrp
                except ValueError:
                    pass

            # STP Configuration
            stp_mode_text = self.stp_mode_combo.currentText()
            stp_priority_text = self.stp_priority_input.text().strip()
            root_primary_text = self.stp_root_primary_input.text().strip()
            root_secondary_text = self.stp_root_secondary_input.text().strip()
            portfast = self.stp_portfast_default.isChecked()
            bpduguard = self.stp_bpduguard_default.isChecked()

            # Only add STP if something is configured
            if stp_priority_text or root_primary_text or root_secondary_text or portfast or bpduguard:
                stp_mode_map = {
                    "rapid-pvst": STPMode.RAPID_PVST,
                    "pvst": STPMode.PVST,
                    "mst": STPMode.MST,
                }
                stp = STPConfig(
                    mode=stp_mode_map.get(stp_mode_text, STPMode.RAPID_PVST),
                    portfast_default=portfast,
                    bpduguard_default=bpduguard,
                )

                if stp_priority_text:
                    try:
                        stp.priority = int(stp_priority_text)
                    except ValueError:
                        pass

                if root_primary_text:
                    try:
                        stp.root_primary_vlans = [int(v.strip()) for v in root_primary_text.split(",") if v.strip()]
                    except ValueError:
                        pass

                if root_secondary_text:
                    try:
                        stp.root_secondary_vlans = [int(v.strip()) for v in root_secondary_text.split(",") if v.strip()]
                    except ValueError:
                        pass

                config.stp = stp

            # Prefix Lists
            prefix_lists_dict = {}  # Group entries by name
            for row_data in self.prefix_list_rows:
                name = row_data["name_input"].text().strip()
                seq_text = row_data["seq_input"].text().strip()
                prefix = row_data["prefix_input"].text().strip()

                if name and seq_text and prefix:
                    try:
                        ge_text = row_data["ge_input"].text().strip()
                        le_text = row_data["le_input"].text().strip()

                        entry = PrefixListEntry(
                            sequence=int(seq_text),
                            action=row_data["action_combo"].currentText(),
                            prefix=prefix,
                            ge=int(ge_text) if ge_text else None,
                            le=int(le_text) if le_text else None,
                        )

                        if name not in prefix_lists_dict:
                            prefix_lists_dict[name] = PrefixList(name=name)
                        prefix_lists_dict[name].entries.append(entry)
                    except ValueError:
                        pass

            config.prefix_lists = list(prefix_lists_dict.values())

            # Route Maps
            route_maps_dict = {}  # Group entries by name
            for row_data in self.routemap_rows:
                name = row_data["name_input"].text().strip()
                seq_text = row_data["seq_input"].text().strip()

                if name and seq_text:
                    try:
                        match_prefix = row_data["match_prefix_input"].text().strip() or None
                        set_lp_text = row_data["set_localpref_input"].text().strip()
                        set_med_text = row_data["set_med_input"].text().strip()
                        set_weight_text = row_data["set_weight_input"].text().strip()

                        entry = RouteMapEntry(
                            sequence=int(seq_text),
                            action=row_data["action_combo"].currentText(),
                            match_prefix_list=match_prefix,
                            set_local_pref=int(set_lp_text) if set_lp_text else None,
                            set_med=int(set_med_text) if set_med_text else None,
                            set_weight=int(set_weight_text) if set_weight_text else None,
                        )

                        if name not in route_maps_dict:
                            route_maps_dict[name] = RouteMap(name=name)
                        route_maps_dict[name].entries.append(entry)
                    except ValueError:
                        pass

            config.route_maps = list(route_maps_dict.values())

            # Generate
            output = self.generator.generate(config)
            self.output_text.setPlainText(output)

            # Validate
            issues = self.validator.validate(config)
            self._display_validation(issues)

            self._show_status(f"Generated configuration for {hostname}")

        except Exception as e:
            self._show_status(f"Error: {str(e)}", error=True)

    def _display_validation(self, issues: list) -> None:
        """Display validation issues."""
        if not issues:
            self.validation_text.setPlainText("No issues found!")
            return

        errors = [i for i in issues if i.severity.value == "error"]
        warnings = [i for i in issues if i.severity.value == "warning"]
        infos = [i for i in issues if i.severity.value == "info"]

        lines = [f"Found: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info\n"]

        for issue in issues:
            icon = {"error": "[ERROR]", "warning": "[WARN]", "info": "[INFO]"}.get(issue.severity.value, "[?]")
            lines.append(f"{icon} {issue.message}")
            lines.append(f"       Location: {issue.location}")
            if issue.recommendation:
                lines.append(f"       Tip: {issue.recommendation}")
            lines.append("")

        self.validation_text.setPlainText("\n".join(lines))

    def _import_syslog_file(self) -> None:
        """Import and parse a syslog file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Syslog File",
            "",
            "Log Files (*.log *.txt);;All Files (*)"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            self.import_text.setPlainText(content)
            self._show_status(f"Loaded syslog file: {Path(file_path).name}")

            # Parse syslog entries and display summary in results
            lines = [
                "SYSLOG FILE IMPORTED",
                "=" * 40,
                "",
                f"File: {Path(file_path).name}",
                f"Total lines: {len(content.splitlines())}",
                "",
                "SYSLOG SUMMARY",
                "-" * 40,
            ]

            # Count severity levels
            syslog_content = content.splitlines()
            severity_counts = {
                "EMERG": 0, "ALERT": 0, "CRIT": 0, "ERR": 0,
                "WARNING": 0, "NOTICE": 0, "INFO": 0, "DEBUG": 0
            }

            for line in syslog_content:
                line_upper = line.upper()
                for severity in severity_counts:
                    if severity in line_upper or f"%{severity}" in line_upper:
                        severity_counts[severity] += 1
                        break

            lines.append("Message Severity Counts:")
            for severity, count in severity_counts.items():
                if count > 0:
                    lines.append(f"  {severity}: {count}")

            total_parsed = sum(severity_counts.values())
            lines.extend([
                "",
                f"Parsed entries: {total_parsed}",
                f"Unparsed lines: {len(syslog_content) - total_parsed}",
                "",
                "TIP: Use 'Parse Configuration' to extract network",
                "configuration from embedded show commands.",
            ])

            self.parse_results_text.setPlainText("\n".join(lines))

        except Exception as e:
            self._show_status(f"Error loading syslog file: {e}", error=True)

    def _parse_config(self) -> None:
        """Parse imported configuration."""
        config_text = self.import_text.toPlainText().strip()

        if not config_text:
            self._show_status("Please paste a configuration first", error=True)
            return

        try:
            result = ConfigParserFactory.detect_and_parse(config_text)

            if result.errors:
                lines = ["ERRORS:"]
                for err in result.errors:
                    lines.append(f"  - {err}")
                self.parse_results_text.setPlainText("\n".join(lines))
                self._show_status("Parse errors occurred", error=True)
                return

            if result.config:
                config = result.config
                lines = [
                    "PARSED CONFIGURATION",
                    "=" * 40,
                    "",
                    f"Hostname: {config.hostname}",
                    f"Vendor: {result.vendor.value if result.vendor else 'Unknown'}",
                    f"Domain: {config.domain_name or 'Not set'}",
                    "",
                    f"Interfaces: {len(config.interfaces)}",
                ]

                for iface in config.interfaces[:5]:
                    lines.append(f"  - {iface.name}: {iface.ip_address or 'no IP'}")
                if len(config.interfaces) > 5:
                    lines.append(f"  ... and {len(config.interfaces) - 5} more")

                lines.extend([
                    "",
                    f"VLANs: {len(config.vlans)}",
                ])
                for vlan in config.vlans[:5]:
                    lines.append(f"  - VLAN {vlan.vlan_id}: {vlan.name}")

                lines.extend([
                    "",
                    f"Static Routes: {len(config.static_routes)}",
                    f"OSPF: {'Configured' if config.ospf else 'Not configured'}",
                    f"BGP: {'Configured' if config.bgp else 'Not configured'}",
                ])

                if result.warnings:
                    lines.extend(["", "WARNINGS:"])
                    for warn in result.warnings:
                        lines.append(f"  - {warn}")

                # Run validation
                issues = self.validator.validate(config)
                if issues:
                    lines.extend(["", f"VALIDATION ({len(issues)} issues):"])
                    for issue in issues[:10]:
                        lines.append(f"  [{issue.severity.value}] {issue.message}")

                self.parse_results_text.setPlainText("\n".join(lines))
                self._show_status(f"Parsed: {config.hostname}")

        except Exception as e:
            self._show_status(f"Parse error: {str(e)}", error=True)

    def _copy_output(self) -> None:
        """Copy output to clipboard."""
        text = self.output_text.toPlainText()
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            self._show_status("Copied to clipboard")

    def _export_config(self) -> None:
        """Export the generated configuration to a file."""
        text = self.output_text.toPlainText()
        if not text:
            self._show_status("No configuration to export", error=True)
            return

        # Get hostname for default filename
        hostname = self.hostname_input[1].text().strip() or "config"

        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Configuration",
            f"{hostname}.cfg",
            "Config Files (*.cfg);;Text Files (*.txt);;All Files (*)",
        )

        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(text)

                self._show_status(f"Configuration exported to {Path(filepath).name}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export configuration: {e}")
                self._show_status(f"Export failed: {e}", error=True)

    def _clear_generate(self) -> None:
        """Clear generate form."""
        self.hostname_input[1].clear()
        self.domain_input[1].clear()
        self.enable_input[1].clear()
        self.dns_input[1].clear()
        self.ntp_input[1].clear()

        # Clear interface rows
        for row_data in self.interface_rows[:]:
            self.interfaces_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.interface_rows.clear()
        # Add one empty row
        self._add_interface_row()

        self.vlans_input.clear()

        # Clear ACL fields
        self.acl_name_input[1].clear()
        self.acl_type_combo.setCurrentIndex(0)
        for row_data in self.acl_entry_rows[:]:
            self.acl_entries_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.acl_entry_rows.clear()

        self.routes_input.clear()

        # Clear OSPF fields
        self.ospf_process_input[1].clear()
        self.ospf_router_id_input[1].clear()
        self.ospf_ref_bw_input[1].clear()
        self.ospf_networks_input.clear()
        self.ospf_passive_input.clear()

        # Clear BGP fields
        self.bgp_as_input[1].clear()
        self.bgp_router_id_input[1].clear()
        self.bgp_networks_input.clear()

        # Clear BGP neighbor rows
        for row_data in self.bgp_neighbor_rows[:]:
            self.bgp_neighbors_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.bgp_neighbor_rows.clear()

        # Clear EIGRP fields
        self.eigrp_as_input.clear()
        self.eigrp_router_id_input.clear()
        self.eigrp_named_mode.setChecked(False)
        self.eigrp_name_input.clear()
        self.eigrp_networks_input.clear()
        self.eigrp_passive_input.clear()

        # Clear STP fields
        self.stp_mode_combo.setCurrentIndex(0)
        self.stp_priority_input.clear()
        self.stp_root_primary_input.clear()
        self.stp_root_secondary_input.clear()
        self.stp_portfast_default.setChecked(False)
        self.stp_bpduguard_default.setChecked(False)

        # Clear prefix list rows
        for row_data in self.prefix_list_rows[:]:
            self.prefix_list_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.prefix_list_rows.clear()

        # Clear route map rows
        for row_data in self.routemap_rows[:]:
            self.routemap_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.routemap_rows.clear()

        self.output_text.clear()
        self.validation_text.clear()
        self._show_status("Form cleared")

    def _get_project_data(self) -> dict:
        """Collect all form data into a dictionary for saving."""
        data = {
            "version": "1.0",
            "basic": {
                "vendor": self.vendor_combo.currentText(),
                "hostname": self.hostname_input[1].text(),
                "domain": self.domain_input[1].text(),
                "enable_secret": self.enable_input[1].text(),
                "dns_servers": self.dns_input[1].text(),
                "ntp_servers": self.ntp_input[1].text(),
            },
            "interfaces": [],
            "vlans": self.vlans_input.toPlainText(),
            "acl": {
                "name": self.acl_name_input[1].text(),
                "type": self.acl_type_combo.currentText(),
                "entries": [],
            },
            "static_routes": self.routes_input.toPlainText(),
            "ospf": {
                "process_id": self.ospf_process_input[1].text(),
                "router_id": self.ospf_router_id_input[1].text(),
                "ref_bandwidth": self.ospf_ref_bw_input[1].text(),
                "networks": self.ospf_networks_input.toPlainText(),
                "passive_interfaces": self.ospf_passive_input.text(),
            },
            "bgp": {
                "local_as": self.bgp_as_input[1].text(),
                "router_id": self.bgp_router_id_input[1].text(),
                "neighbors": [],
                "networks": self.bgp_networks_input.toPlainText(),
            },
        }

        # Collect interfaces
        for row_data in self.interface_rows:
            data["interfaces"].append({
                "type": row_data["type_combo"].currentText(),
                "number": row_data["number_input"].text(),
                "description": row_data["desc_input"].text(),
                "ip": row_data["ip_input"].text(),
                "mask": row_data["mask_input"].text(),
            })

        # Collect ACL entries
        for row_data in self.acl_entry_rows:
            data["acl"]["entries"].append({
                "seq": row_data["seq_input"].text(),
                "action": row_data["action_combo"].currentText(),
                "protocol": row_data["protocol_combo"].currentText(),
                "source": row_data["source_input"].text(),
                "src_wildcard": row_data["src_wc_input"].text(),
                "destination": row_data["dest_input"].text(),
                "dst_wildcard": row_data["dst_wc_input"].text(),
                "dst_port": row_data["dst_port_input"].text(),
                "log": row_data["log_combo"].currentText(),
            })

        # Collect BGP neighbors
        for row_data in self.bgp_neighbor_rows:
            data["bgp"]["neighbors"].append({
                "ip": row_data["ip_input"].text(),
                "remote_as": row_data["as_input"].text(),
                "description": row_data["desc_input"].text(),
                "update_source": row_data["update_src_input"].text(),
                "multihop": row_data["multihop_input"].text(),
            })

        # EIGRP
        data["eigrp"] = {
            "as_number": self.eigrp_as_input.text(),
            "router_id": self.eigrp_router_id_input.text(),
            "named_mode": self.eigrp_named_mode.isChecked(),
            "name": self.eigrp_name_input.text(),
            "networks": self.eigrp_networks_input.toPlainText(),
            "passive_interfaces": self.eigrp_passive_input.text(),
        }

        # STP
        data["stp"] = {
            "mode": self.stp_mode_combo.currentText(),
            "priority": self.stp_priority_input.text(),
            "root_primary_vlans": self.stp_root_primary_input.text(),
            "root_secondary_vlans": self.stp_root_secondary_input.text(),
            "portfast_default": self.stp_portfast_default.isChecked(),
            "bpduguard_default": self.stp_bpduguard_default.isChecked(),
        }

        # Prefix Lists
        data["prefix_lists"] = []
        for row_data in self.prefix_list_rows:
            data["prefix_lists"].append({
                "name": row_data["name_input"].text(),
                "seq": row_data["seq_input"].text(),
                "action": row_data["action_combo"].currentText(),
                "prefix": row_data["prefix_input"].text(),
                "ge": row_data["ge_input"].text(),
                "le": row_data["le_input"].text(),
            })

        # Route Maps
        data["route_maps"] = []
        for row_data in self.routemap_rows:
            data["route_maps"].append({
                "name": row_data["name_input"].text(),
                "seq": row_data["seq_input"].text(),
                "action": row_data["action_combo"].currentText(),
                "match_prefix": row_data["match_prefix_input"].text(),
                "set_localpref": row_data["set_localpref_input"].text(),
                "set_med": row_data["set_med_input"].text(),
                "set_weight": row_data["set_weight_input"].text(),
            })

        return data

    def _load_template(self, template_name: str) -> None:
        """Load a configuration template."""
        if template_name == "-- Select Template --" or template_name not in self.TEMPLATES:
            return

        template = self.TEMPLATES[template_name]
        self._load_project_data(template)
        self._show_status(f"Loaded template: {template_name}")

        # Reset template dropdown to placeholder
        self.template_combo.blockSignals(True)
        self.template_combo.setCurrentIndex(0)
        self.template_combo.blockSignals(False)

    def _load_project_data(self, data: dict) -> None:
        """Load form data from a dictionary."""
        # Clear existing data first
        self._clear_generate()

        # Basic settings
        basic = data.get("basic", {})
        vendor = basic.get("vendor", "")
        if vendor:
            index = self.vendor_combo.findText(vendor)
            if index >= 0:
                self.vendor_combo.setCurrentIndex(index)
        self.hostname_input[1].setText(basic.get("hostname", ""))
        self.domain_input[1].setText(basic.get("domain", ""))
        self.enable_input[1].setText(basic.get("enable_secret", ""))
        self.dns_input[1].setText(basic.get("dns_servers", ""))
        self.ntp_input[1].setText(basic.get("ntp_servers", ""))

        # Interfaces - clear default and add from data
        for row_data in self.interface_rows[:]:
            self.interfaces_layout.removeWidget(row_data["widget"])
            row_data["widget"].deleteLater()
        self.interface_rows.clear()

        for iface in data.get("interfaces", []):
            self._add_interface_row(
                iface_type=iface.get("type", "GigabitEthernet"),
                number=iface.get("number", ""),
                description=iface.get("description", ""),
                ip=iface.get("ip", ""),
                mask=iface.get("mask", ""),
            )

        # If no interfaces loaded, add a blank one
        if not self.interface_rows:
            self._add_interface_row()

        # VLANs
        self.vlans_input.setPlainText(data.get("vlans", ""))

        # ACL
        acl_data = data.get("acl", {})
        self.acl_name_input[1].setText(acl_data.get("name", ""))
        acl_type = acl_data.get("type", "Extended")
        index = self.acl_type_combo.findText(acl_type)
        if index >= 0:
            self.acl_type_combo.setCurrentIndex(index)

        for entry in acl_data.get("entries", []):
            self._add_acl_entry_row()
            row_data = self.acl_entry_rows[-1]
            row_data["seq_input"].setText(entry.get("seq", ""))
            action_idx = row_data["action_combo"].findText(entry.get("action", "permit"))
            if action_idx >= 0:
                row_data["action_combo"].setCurrentIndex(action_idx)
            protocol_idx = row_data["protocol_combo"].findText(entry.get("protocol", "ip"))
            if protocol_idx >= 0:
                row_data["protocol_combo"].setCurrentIndex(protocol_idx)
            row_data["source_input"].setText(entry.get("source", ""))
            row_data["src_wc_input"].setText(entry.get("src_wildcard", ""))
            row_data["dest_input"].setText(entry.get("destination", ""))
            row_data["dst_wc_input"].setText(entry.get("dst_wildcard", ""))
            row_data["dst_port_input"].setText(entry.get("dst_port", ""))
            log_idx = row_data["log_combo"].findText(entry.get("log", ""))
            if log_idx >= 0:
                row_data["log_combo"].setCurrentIndex(log_idx)

        # Static routes
        self.routes_input.setPlainText(data.get("static_routes", ""))

        # OSPF
        ospf_data = data.get("ospf", {})
        self.ospf_process_input[1].setText(ospf_data.get("process_id", ""))
        self.ospf_router_id_input[1].setText(ospf_data.get("router_id", ""))
        self.ospf_ref_bw_input[1].setText(ospf_data.get("ref_bandwidth", ""))
        self.ospf_networks_input.setPlainText(ospf_data.get("networks", ""))
        self.ospf_passive_input.setText(ospf_data.get("passive_interfaces", ""))

        # BGP
        bgp_data = data.get("bgp", {})
        self.bgp_as_input[1].setText(bgp_data.get("local_as", ""))
        self.bgp_router_id_input[1].setText(bgp_data.get("router_id", ""))
        self.bgp_networks_input.setPlainText(bgp_data.get("networks", ""))

        for neighbor in bgp_data.get("neighbors", []):
            self._add_bgp_neighbor_row()
            row_data = self.bgp_neighbor_rows[-1]
            row_data["ip_input"].setText(neighbor.get("ip", ""))
            row_data["as_input"].setText(neighbor.get("remote_as", ""))
            row_data["desc_input"].setText(neighbor.get("description", ""))
            row_data["update_src_input"].setText(neighbor.get("update_source", ""))
            row_data["multihop_input"].setText(neighbor.get("multihop", ""))

        # EIGRP
        eigrp_data = data.get("eigrp", {})
        self.eigrp_as_input.setText(eigrp_data.get("as_number", ""))
        self.eigrp_router_id_input.setText(eigrp_data.get("router_id", ""))
        self.eigrp_named_mode.setChecked(eigrp_data.get("named_mode", False))
        self.eigrp_name_input.setText(eigrp_data.get("name", ""))
        self.eigrp_networks_input.setPlainText(eigrp_data.get("networks", ""))
        self.eigrp_passive_input.setText(eigrp_data.get("passive_interfaces", ""))

        # STP
        stp_data = data.get("stp", {})
        stp_mode = stp_data.get("mode", "rapid-pvst")
        mode_idx = self.stp_mode_combo.findText(stp_mode)
        if mode_idx >= 0:
            self.stp_mode_combo.setCurrentIndex(mode_idx)
        self.stp_priority_input.setText(stp_data.get("priority", ""))
        self.stp_root_primary_input.setText(stp_data.get("root_primary_vlans", ""))
        self.stp_root_secondary_input.setText(stp_data.get("root_secondary_vlans", ""))
        self.stp_portfast_default.setChecked(stp_data.get("portfast_default", False))
        self.stp_bpduguard_default.setChecked(stp_data.get("bpduguard_default", False))

        # Prefix Lists
        for pl_entry in data.get("prefix_lists", []):
            self._add_prefix_list_row(
                name=pl_entry.get("name", ""),
                seq=int(pl_entry.get("seq", 10)) if pl_entry.get("seq") else 10,
                action=pl_entry.get("action", "permit"),
                prefix=pl_entry.get("prefix", ""),
                ge=pl_entry.get("ge", ""),
                le=pl_entry.get("le", ""),
            )

        # Route Maps
        for rm_entry in data.get("route_maps", []):
            self._add_routemap_row(
                name=rm_entry.get("name", ""),
                seq=int(rm_entry.get("seq", 10)) if rm_entry.get("seq") else 10,
                action=rm_entry.get("action", "permit"),
                match_prefix=rm_entry.get("match_prefix", ""),
                set_localpref=rm_entry.get("set_localpref", ""),
                set_med=rm_entry.get("set_med", ""),
                set_weight=rm_entry.get("set_weight", ""),
            )

    def _save_project(self) -> None:
        """Save the current project to a JSON file."""
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Project",
            "",
            "NetConfigPro Project (*.ncpro);;JSON Files (*.json);;All Files (*)",
        )

        if filepath:
            try:
                # Ensure extension
                if not filepath.endswith((".ncpro", ".json")):
                    filepath += ".ncpro"

                data = self._get_project_data()

                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2)

                self._show_status(f"Project saved to {Path(filepath).name}")
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Failed to save project: {e}")
                self._show_status(f"Save failed: {e}", error=True)

    def _load_project(self) -> None:
        """Load a project from a JSON file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Load Project",
            "",
            "NetConfigPro Project (*.ncpro);;JSON Files (*.json);;All Files (*)",
        )

        if filepath:
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)

                self._load_project_data(data)
                self._show_status(f"Project loaded from {Path(filepath).name}")
            except json.JSONDecodeError as e:
                QMessageBox.critical(self, "Load Error", f"Invalid project file: {e}")
                self._show_status("Load failed: Invalid file", error=True)
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Failed to load project: {e}")
                self._show_status(f"Load failed: {e}", error=True)

    def _show_status(self, message: str, error: bool = False) -> None:
        """Update status bar."""
        self.status_bar.showMessage(message)
        if error:
            self.status_bar.setStyleSheet(f"color: {COLORS['error']};")
        else:
            self.status_bar.setStyleSheet(f"color: {COLORS['text_secondary']};")

    # Real-time validation methods
    def _validate_ip(self, text: str) -> bool:
        """Validate IP address format."""
        if not text:
            return True  # Empty is valid (optional field)
        return bool(self.IP_PATTERN.match(text))

    def _validate_mask(self, text: str) -> bool:
        """Validate subnet mask format."""
        if not text:
            return True  # Empty is valid (optional field)
        return bool(self.MASK_PATTERN.match(text))

    def _validate_hostname(self, text: str) -> bool:
        """Validate hostname format."""
        if not text:
            return False  # Hostname is required
        return bool(self.HOSTNAME_PATTERN.match(text))

    def _validate_domain(self, text: str) -> bool:
        """Validate domain name format."""
        if not text:
            return True  # Domain is optional
        return bool(self.DOMAIN_PATTERN.match(text))

    def _validate_as_number(self, text: str) -> bool:
        """Validate AS number."""
        if not text:
            return True  # Optional
        try:
            as_num = int(text)
            return 1 <= as_num <= 4294967295
        except ValueError:
            return False

    def _validate_integer(self, text: str, min_val: int = 0, max_val: int = 65535) -> bool:
        """Validate integer within range."""
        if not text:
            return True
        try:
            val = int(text)
            return min_val <= val <= max_val
        except ValueError:
            return False

    def _apply_validation(self, widget: QLineEdit, is_valid: bool) -> None:
        """Apply visual validation feedback to a widget."""
        if is_valid:
            widget.setStyleSheet(self.VALID_STYLE)
        else:
            widget.setStyleSheet(self.INVALID_STYLE)

    def _setup_validation_for_input(self, widget: QLineEdit, validator_func) -> None:
        """Connect validation to an input's textChanged signal."""
        def validate():
            text = widget.text()
            is_valid = validator_func(text)
            self._apply_validation(widget, is_valid)
        widget.textChanged.connect(validate)

    def _setup_interface_validation(self, row_data: dict) -> None:
        """Setup validation for interface row inputs."""
        ip_input = row_data["ip_input"]
        mask_input = row_data["mask_input"]

        # Validate IP
        def validate_ip():
            is_valid = self._validate_ip(ip_input.text())
            self._apply_validation(ip_input, is_valid)
        ip_input.textChanged.connect(validate_ip)

        # Validate subnet mask
        def validate_mask():
            is_valid = self._validate_mask(mask_input.text())
            self._apply_validation(mask_input, is_valid)
        mask_input.textChanged.connect(validate_mask)

    def _setup_bgp_neighbor_validation(self, row_data: dict) -> None:
        """Setup validation for BGP neighbor row inputs."""
        ip_input = row_data["ip_input"]
        as_input = row_data["as_input"]

        # Validate neighbor IP
        def validate_ip():
            is_valid = self._validate_ip(ip_input.text())
            self._apply_validation(ip_input, is_valid)
        ip_input.textChanged.connect(validate_ip)

        # Validate AS number
        def validate_as():
            is_valid = self._validate_as_number(as_input.text())
            self._apply_validation(as_input, is_valid)
        as_input.textChanged.connect(validate_as)

    def _setup_basic_validation(self) -> None:
        """Setup validation for basic settings inputs."""
        # Hostname validation
        hostname_input = self.hostname_input[1]
        def validate_hostname():
            is_valid = self._validate_hostname(hostname_input.text())
            self._apply_validation(hostname_input, is_valid)
        hostname_input.textChanged.connect(validate_hostname)

        # Domain validation
        domain_input = self.domain_input[1]
        def validate_domain():
            is_valid = self._validate_domain(domain_input.text())
            self._apply_validation(domain_input, is_valid)
        domain_input.textChanged.connect(validate_domain)

        # OSPF router ID validation
        ospf_router_id = self.ospf_router_id_input[1]
        def validate_ospf_rid():
            is_valid = self._validate_ip(ospf_router_id.text())
            self._apply_validation(ospf_router_id, is_valid)
        ospf_router_id.textChanged.connect(validate_ospf_rid)

        # BGP AS validation
        bgp_as = self.bgp_as_input[1]
        def validate_bgp_as():
            is_valid = self._validate_as_number(bgp_as.text())
            self._apply_validation(bgp_as, is_valid)
        bgp_as.textChanged.connect(validate_bgp_as)

        # BGP router ID validation
        bgp_router_id = self.bgp_router_id_input[1]
        def validate_bgp_rid():
            is_valid = self._validate_ip(bgp_router_id.text())
            self._apply_validation(bgp_router_id, is_valid)
        bgp_router_id.textChanged.connect(validate_bgp_rid)


def main() -> None:
    """Run the application."""
    app = QApplication(sys.argv)
    app.setStyleSheet(DARK_STYLESHEET)

    window = NetConfigProApp()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
