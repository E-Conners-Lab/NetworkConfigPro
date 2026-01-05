# NetConfigPro Test Guide

## Test Data Files

All test files are in `test_data/` directory.

---

## TAB 1: Generate Configuration

### Test Basic Router Generation
1. Select **Vendor**: Cisco IOS/IOS-XE
2. Select **Template**: Basic Router (or leave blank)
3. Fill in:
   - **Hostname**: `LAB-ROUTER-01`
   - **Domain**: `testlab.local`
   - **Enable Secret**: `cisco123`
   - **DNS Servers**: `8.8.8.8, 1.1.1.1`
   - **NTP Servers**: `pool.ntp.org`

4. **Add Interfaces** (click "+ Add Interface" for each):
   | Type | Number | Description | IP Address | Subnet Mask |
   |------|--------|-------------|------------|-------------|
   | GigabitEthernet | 0/0 | WAN Link | 203.0.113.1 | 255.255.255.252 |
   | GigabitEthernet | 0/1 | LAN | 192.168.1.1 | 255.255.255.0 |
   | Loopback | 0 | Router ID | 10.255.255.1 | 255.255.255.255 |

5. **Add VLANs** (in VLAN text area, one per line as `ID,NAME`):
   ```
   10,MANAGEMENT
   20,USERS
   30,SERVERS
   ```

6. **OSPF Configuration**:
   - Process ID: `1`
   - Router ID: `10.255.255.1`
   - Reference Bandwidth: `10000`
   - Networks: `192.168.1.0/24 area 0`
   - Passive Interfaces: `GigabitEthernet0/1`

7. Click **Generate** button
8. Test **Copy to Clipboard** button
9. Test **Export to File** button
10. Test **Clear** button
11. Test **Save Project** / **Load Project** buttons

---

## TAB 2: Import Configuration

### Test Config Parsing
1. Go to **Import** tab
2. Copy contents of `test_data/sample_cisco_config.txt` and paste into text area
3. Click **Parse Configuration**
4. Verify results show:
   - Hostname: TEST-ROUTER-01
   - Vendor detected: Cisco IOS
   - Interfaces listed
   - VLANs listed
   - OSPF/BGP detected

### Test Syslog Import
1. Click **Import Syslog File** button
2. Select `test_data/sample_syslog.log`
3. Verify:
   - File loads into text area
   - Summary shows severity counts (should show ALERT: 1, CRIT: 1, ERR: 2, WARNING: 1, etc.)

---

## TAB 3: Diff Configuration

### Test Configuration Comparison
1. Go to **Diff** tab
2. Paste contents of `test_data/config_original.txt` into **Configuration A**
3. Paste contents of `test_data/config_modified.txt` into **Configuration B**
4. Click **Compare**
5. Verify diff shows:
   - Hostname change (CORE-SW-01 → CORE-SW-01-UPDATED)
   - New interface GigabitEthernet0/3
   - New Vlan30
   - New VLAN 30 SERVERS
   - Additional OSPF networks
   - New static route
6. Test **Clear** button

---

## TAB 4: Vault (Secure Storage)

### Test Vault Creation
1. Go to **Vault** tab
2. Enter master password: `TestPassword123!`
3. Click **Unlock** (creates new vault if none exists)

### Test Credential Storage
1. Add credential:
   - Username: `admin`
   - Password: `SuperSecret123`
2. Click **Add Credential**
3. Verify it appears in list

### Test Variable Storage
1. Add variable:
   - Name: `SNMP_COMMUNITY`
   - Value: `public123`
2. Click **Add Variable**
3. Verify it appears in list

### Test Lock/Unlock
1. Click **Lock**
2. Verify vault locks
3. Re-enter password and **Unlock**
4. Verify credentials/variables still present

---

## TAB 5: Help

1. Go to **Help** tab
2. Scroll through documentation
3. Verify content is readable

---

## Button Animation Tests

For each button, verify press animation:
- Button should visibly "push down" when clicked
- Border should appear on press
- Color should darken
- Effect should be noticeable and satisfying

### Buttons to test:
- [ ] Sidebar navigation buttons (Generate, Import, Diff, Vault, Help)
- [ ] Green "success" buttons (Generate, Parse Configuration, Compare)
- [ ] Gray "secondary" buttons (Clear, Import Syslog File)
- [ ] Blue "primary" buttons (Save Project, Load Project, Copy, Export)
- [ ] Add buttons (+Add Interface, +Add ACL Entry, etc.)

---

## Keyboard Shortcuts

Test these shortcuts:
- `Ctrl+1` → Generate tab
- `Ctrl+2` → Import tab
- `Ctrl+3` → Diff tab
- `Ctrl+4` → Vault tab
- `Ctrl+5` → Help tab
