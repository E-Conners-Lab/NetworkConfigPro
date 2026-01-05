# NetConfigPro

A network configuration generator and validator for multi-vendor network devices.

## Features

- **Multi-vendor support**: Generate configurations for Cisco IOS/IOS-XE, NX-OS, Arista EOS, Juniper Junos, and SONiC
- **Configuration validation**: Catch errors and get best-practice recommendations before deployment
- **Import & analyze**: Parse existing configurations and identify issues
- **Configuration diff**: Compare two configurations side-by-side
- **Secure vault**: Encrypted storage for credentials and sensitive variables
- **Modern GUI**: Clean, dark-themed interface with PySide6

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd netconfigpro

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Run the application
python main.py
```

### Quick Start

1. **Generate Configuration**
   - Select your target vendor (Cisco IOS, NX-OS, Arista EOS, Juniper, SONiC)
   - Fill in hostname, interfaces, VLANs, routing configuration
   - Click "Generate" or press `Ctrl+G`
   - Review validation results and export

2. **Import Configuration**
   - Paste an existing configuration or open a file
   - Click "Parse Configuration"
   - Review parsed elements and validation issues

3. **Compare Configurations**
   - Use the Diff tab to compare two configurations
   - See additions, deletions, and changes highlighted

4. **Secure Vault**
   - Create a vault with a master password
   - Store credentials and template variables securely
   - All data is encrypted at rest

## Supported Vendors & Configuration Elements

| Element | Cisco IOS | NX-OS | Arista EOS | Juniper | SONiC |
|---------|-----------|-------|------------|---------|-------|
| Interfaces | Yes | Yes | Yes | Yes | Yes |
| VLANs | Yes | Yes | Yes | Yes | Yes |
| ACLs | Yes | Yes | Yes | Yes | Yes |
| Static Routes | Yes | Yes | Yes | Yes | Yes |
| OSPF | Yes | Yes | Yes | Yes | - |
| BGP | Yes | Yes | Yes | Yes | Yes |

### SONiC Support

SONiC configurations are generated in `config_db.json` format with support for:

- **DEVICE_METADATA**: Hostname, BGP ASN, device type
- **PORT**: Interface configuration with MTU (default 9100)
- **INTERFACE / LOOPBACK_INTERFACE**: L3 addressing
- **VLAN / VLAN_MEMBER / VLAN_INTERFACE**: VLAN configuration
- **BGP_NEIGHBOR**: BGP peering with `rmt_asn` field format
- **STATIC_ROUTE**: Static routing
- **ACL_TABLE / ACL_RULE**: L3 ACLs
- **NTP_SERVER / DNS_NAMESERVER**: Management services

Interface naming is automatically converted:
- `GigabitEthernet0/0` → `Ethernet0`
- `Ethernet0/1` → `Ethernet1` (slot/port to flat numbering)
- `Loopback0` → `Loopback0`

## Project Structure

```
netconfigpro/
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
├── src/
│   ├── core/
│   │   ├── models.py        # Data models
│   │   ├── generators/      # Config generation
│   │   │   └── config_generator.py
│   │   ├── validators/      # Validation rules
│   │   ├── parsers/         # Config parsing
│   │   │   └── config_parser.py
│   │   └── templates/
│   │       └── vendors/     # Jinja2 templates
│   │           ├── cisco_ios.j2
│   │           ├── cisco_nxos.j2
│   │           ├── arista_eos.j2
│   │           ├── juniper_junos.j2
│   │           └── sonic.j2
│   ├── security/            # Encryption, vault
│   └── gui/                 # PySide6 GUI
├── tests/
│   └── unit/
│       ├── test_generator.py
│       ├── test_parser.py
│       ├── test_sonic.py
│       ├── test_all_templates.py
│       └── ...
└── docs/                    # Documentation
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run SONiC-specific tests
python -m pytest tests/unit/test_sonic.py -v

# Run all template tests
python -m pytest tests/unit/test_all_templates.py -v

# Run with coverage
python -m pytest tests/ --cov=src
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+1-5 | Switch tabs |
| Ctrl+G | Generate configuration |
| Ctrl+S | Save project |
| Ctrl+O | Open project |
| Ctrl+E | Export configuration |
| Ctrl+L | Clear form |
| Ctrl+I | Add interface |
| Ctrl+Shift+C | Copy output |

## Security

- All sensitive data is encrypted using AES-256 (Fernet)
- PBKDF2 with 480,000 iterations for key derivation
- Vault files use restrictive permissions (600)
- No plaintext secrets stored on disk

## Requirements

- Python 3.10+
- PySide6
- Jinja2
- cryptography

## License

MIT License
