sta# NetConfigPro Test Guide

## How to Run the App
```bash
cd netconfigpro
python3 main.py
```

---

## Feature Testing Checklist

### 1. Generate Tab - Basic Configuration

**Test Data:**
- Hostname: `test-router-01`
- Domain: `test.example.com`
- Enable Secret: `TestPass123`
- DNS Servers: `8.8.8.8, 1.1.1.1`
- NTP Servers: `pool.ntp.org`

**Test Steps:**
1. Enter the data above
2. Click "Generate" or press `Ctrl+G`
3. Verify configuration appears in output
4. Click "Copy to Clipboard" or press `Ctrl+Shift+C`

---

### 2. Interface Configuration

**Test Data:**
| Type | Number | Description | IP | Mask |
|------|--------|-------------|-----|------|
| GigabitEthernet | 0/0 | WAN Link | 203.0.113.1 | 255.255.255.252 |
| GigabitEthernet | 0/1 | LAN | 192.168.1.1 | 255.255.255.0 |
| Loopback | 0 | Router ID | 10.0.0.1 | 255.255.255.255 |

**Test Steps:**
1. Add interfaces using "+ Add Interface" or `Ctrl+I`
2. Enter data from table
3. Try invalid IP (e.g., `999.999.999.999`) - should show red border
4. Try invalid mask (e.g., `255.255.255.999`) - should show red border

---

### 3. VLAN Configuration

**Test Data (paste in VLANs box):**
```
10,MANAGEMENT
20,USERS
30,SERVERS
40,VOICE
99,NATIVE
```

---

### 4. ACL Configuration

**Test Data:**
- ACL Name: `OUTSIDE-IN`
- Type: Extended

| Seq | Action | Protocol | Source | Src WC | Destination | Dst WC | Dst Port | Log |
|-----|--------|----------|--------|--------|-------------|--------|----------|-----|
| 10 | permit | tcp | any | | 192.168.1.0 | 0.0.0.255 | eq 443 | |
| 20 | permit | tcp | any | | 192.168.1.0 | 0.0.0.255 | eq 22 | |
| 30 | permit | icmp | any | | any | | | |
| 100 | deny | ip | any | | any | | | log |

---

### 5. Static Routes

**Test Data (paste in Static Routes box):**
```
0.0.0.0,0.0.0.0,203.0.113.2
10.0.0.0,255.0.0.0,192.168.1.254
172.16.0.0,255.240.0.0,192.168.1.254
```

---

### 6. OSPF Configuration

**Test Data:**
- Process ID: `1`
- Router ID: `10.0.0.1`
- Reference Bandwidth: `10000`
- Networks:
  ```
  192.168.1.0,0.0.0.255,0
  10.0.0.1,0.0.0.0,0
  ```
- Passive Interfaces: `GigabitEthernet0/1, Loopback0`

---

### 7. BGP Configuration

**Test Data:**
- Local AS: `65001`
- Router ID: `10.0.0.1`

**Neighbors:**
| IP | Remote AS | Description | Update Source | Multihop |
|----|-----------|-------------|---------------|----------|
| 203.0.113.2 | 65000 | ISP Peering | | |
| 10.255.255.2 | 65001 | iBGP Peer | Loopback0 | 2 |

**Networks:**
```
192.168.1.0/24
10.0.0.0/8
```

---

### 8. Templates

**Test Steps:**
1. Select "Basic Router" from Template dropdown
2. Verify form populates with template data
3. Try other templates: L3 Switch, Edge Router with BGP, Juniper Edge Router, Data Center Spine
4. Change vendor dropdown to see how interface names change

---

### 9. Save/Load Project

**Test Steps:**
1. Fill in form with test data
2. Click "Save Project" or press `Ctrl+S`
3. Save as `my_test_project.ncpro`
4. Click "Clear" or press `Ctrl+L`
5. Click "Load Project" or press `Ctrl+O`
6. Load `test_data/test_project_full.ncpro`
7. Verify all data loads correctly

---

### 10. Export Configuration

**Test Steps:**
1. Generate a configuration
2. Click "Export to File" or press `Ctrl+E`
3. Save as `test_config.cfg`
4. Open the file and verify contents

---

### 11. Real-time Validation

**Test Invalid Inputs:**
| Field | Invalid Value | Expected |
|-------|---------------|----------|
| Hostname | `123invalid` | Red border (must start with letter) |
| IP Address | `192.168.1.999` | Red border |
| Subnet Mask | `255.255.300.0` | Red border |
| BGP AS | `5000000000` | Red border (max 4294967295) |
| Domain | `invalid` | Red border (needs TLD) |

**Valid Values:**
| Field | Valid Value | Expected |
|-------|-------------|----------|
| Hostname | `router1` | No border |
| IP Address | `10.0.0.1` | No border |
| Subnet Mask | `255.255.255.0` | No border |
| BGP AS | `65001` | No border |
| Domain | `example.com` | No border |

---

### 12. Import Tab

**Test Data (paste a Cisco config):**
```
hostname imported-router
!
interface GigabitEthernet0/0
 ip address 10.1.1.1 255.255.255.0
 description Test Interface
!
interface GigabitEthernet0/1
 ip address 10.2.2.1 255.255.255.0
!
router ospf 1
 network 10.0.0.0 0.255.255.255 area 0
!
end
```

**Test Steps:**
1. Go to Import tab (`Ctrl+2`)
2. Paste config above
3. Click "Parse Configuration"
4. Verify parsed results show hostname, interfaces, OSPF

---

### 13. Diff Tab

**Test Steps:**
1. Go to Diff tab (`Ctrl+3`)
2. Open `test_data/test_config_a.txt` and paste in left panel
3. Open `test_data/test_config_b.txt` and paste in right panel
4. Click "Compare"
5. Verify diff shows:
   - Description change on GigabitEthernet0/0
   - New GigabitEthernet0/2 interface
   - New OSPF network and passive-interface
   - New BGP configuration

**Expected Diff Output:**
- Red lines (-): removed/changed from original
- Green lines (+): added/changed in new version
- Stats should show additions and deletions count

---

### 14. Vault Tab

**Test Steps:**
1. Go to Vault tab (`Ctrl+4`)
2. If no vault exists:
   - Enter master password: `TestVault123`
   - Click "Create Vault"
3. If vault exists:
   - Enter password and click "Unlock"

**Test Credentials:**
| Name | Username | Password | Description |
|------|----------|----------|-------------|
| core-router | admin | C0reP@ss! | Core router credentials |
| edge-switch | netadmin | Sw1tchP@ss | Edge switch access |

**Test Variables:**
| Name | Value | Type |
|------|-------|------|
| SNMP_COMMUNITY | public123 | Normal |
| TACACS_KEY | T@c@csS3cr3t | Secret |
| NTP_SERVER | pool.ntp.org | Normal |

**Test Steps:**
1. Add credentials using form
2. Verify they appear in list
3. Add variables
4. Verify secret variables show ********
5. Test delete functionality
6. Click "Lock" and verify vault locks
7. Unlock again to verify password works

---

### 15. Keyboard Shortcuts

**Test All Shortcuts:**
| Shortcut | Action | Tab |
|----------|--------|-----|
| `Ctrl+1` | Switch to Generate | Any |
| `Ctrl+2` | Switch to Import | Any |
| `Ctrl+3` | Switch to Diff | Any |
| `Ctrl+4` | Switch to Vault | Any |
| `Ctrl+5` | Switch to Help | Any |
| `Ctrl+G` | Generate config | Generate |
| `Ctrl+S` | Save project | Generate |
| `Ctrl+O` | Load project | Generate |
| `Ctrl+E` | Export config | Generate |
| `Ctrl+Shift+C` | Copy output | Generate |
| `Ctrl+L` | Clear form | Generate |
| `Ctrl+I` | Add interface | Generate |

---

### 16. Multi-Vendor Testing

**Test each vendor generates correct syntax:**

1. **Cisco IOS/IOS-XE**: `interface GigabitEthernet0/0`
2. **Cisco NX-OS**: `interface Ethernet1/1`
3. **Arista EOS**: `interface Ethernet1`
4. **Juniper Junos**: `set interfaces ge-0/0/0`

**Test Steps:**
1. Create a simple config with one interface
2. Generate for each vendor
3. Verify interface naming matches vendor conventions

---

## Sample Test Files Location

All test files are in: `test_data/`

- `test_config_a.txt` - Original config for diff testing
- `test_config_b.txt` - Modified config for diff testing
- `test_project_full.ncpro` - Complete project file for load testing
- `TEST_GUIDE.md` - This file

---

## Quick Smoke Test

Run these steps for a quick functionality check:

1. Start app: `python3 main.py`
2. Select "Edge Router with BGP" template
3. Press `Ctrl+G` to generate
4. Press `Ctrl+E` to export
5. Press `Ctrl+3` to go to Diff tab
6. Paste any two configs and compare
7. Press `Ctrl+4` to go to Vault
8. Create vault with password "test1234"
9. Add a test credential
10. Lock and unlock vault

If all steps work, core functionality is operational!
