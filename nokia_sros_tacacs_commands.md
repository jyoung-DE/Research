# Nokia SR OS TACACS+ Command Reference

## Complete TACACS+ CLI Command Lines for Detection Engineering

This document contains all TACACS+ related command lines extracted from Nokia SR OS documentation for use in detection engineering and log analysis.

---

## 1. TACACS+ Configuration Context Commands

### Enter TACACS+ Configuration
```
config>system>security>tacplus
configure system security tacplus
```

### Exit/Navigate Commands
```
config>system>security>tacplus# back
config>system>security>tacplus# exit
```

---

## 2. TACACS+ Server Configuration

### Add TACACS+ Server
```
server <server-index> address <ip-address> secret <key>
server <server-index> address <ip-address> secret <key> [hash | hash2]
server <server-index> address <ip-address> secret <key> [hash | hash2] [port <port>]
no server <server-index>
```

**Parameters:**
- `server-index`: 1 to 5 (up to 5 servers can be configured)
- `ip-address`: IPv4 (a.b.c.d) or IPv6 format
- `key`: Secret key up to 128 characters
- `port`: 0 to 65535 (default TCP port 49)

**Examples:**
```
server 1 address 10.10.0.5 secret "test1"
server 2 address 10.10.0.6 secret "test2"
server 3 address 10.10.0.7 secret "test3"
server 4 address 10.10.0.8 secret "test4"
server 5 address 10.10.0.9 secret "test5"
server 1 address 192.168.1.47 secret "tac_secret"
server 1 address 192.168.1.47 secret "1mSYRiobfhHAdFA9cZH3wBviQtXKFDld" hash2
```

---

## 3. TACACS+ Authentication Commands

### Enable/Disable TACACS+ 
```
[no] shutdown
```

### Configure Timeout
```
timeout <seconds>
no timeout
```

**Parameters:**
- `seconds`: 1 to 90 (default: 3 seconds)

**Example:**
```
timeout 5
```

---

## 4. TACACS+ Authorization Commands

### Enable Authorization
```
authorization
no authorization
```

### Enable Authorization with Privilege Level Mapping
```
authorization use-priv-lvl
```

### Configure Privilege Level Mapping
```
priv-lvl-map
priv-lvl <level> "<profile-name>"
```

**Parameters:**
- `level`: Privilege level (typically 1-15)
- `profile-name`: Local profile name to map to

**Examples:**
```
priv-lvl-map
priv-lvl 1 "limited"
priv-lvl 15 "administrative"
```

---

## 5. TACACS+ Accounting Commands

### Enable Accounting
```
accounting
accounting [record-type {start-stop | stop-only}]
no accounting
```

**Parameters:**
- `start-stop`: Send both start and stop packets
- `stop-only`: Send only stop packets (default)

---

## 6. TACACS+ Template Commands

### Use Default Template
```
[no] use-default-template
```

---

## 7. Password Authentication Order Commands

### Configure Authentication Order
```
authentication-order [method-1] [method-2] [method-3] [exit-on-reject]
no authentication-order
```

**Valid Methods:**
- `radius`
- `tacplus`
- `local`

**Examples:**
```
authentication-order tacplus local
authentication-order tacplus local exit-on-reject
authentication-order radius tacplus local
authentication-order radius tacplus local exit-on-reject
```

---

## 8. Health Check Commands

### Configure AAA Server Health Check
```
health-check
health-check [interval <interval>]
no health-check
```

**Parameters:**
- `interval`: 6 to 1500 seconds (default: 30)

---

## 9. Enable-Admin Control Commands

### Enable Admin Control with TACACS+ Mapping
```
enable-admin-control
tacplus-map-to-priv-lvl [admin-priv-lvl]
no tacplus-map-to-priv-lvl
```

---

## 10. Source Address Commands

### Configure TACACS+ Source Address
```
source-address
application tacplus [ip-int-name | ip-address]
application6 tacplus <ipv6-address>
no application tacplus
no application6 tacplus
```

---

## 11. User Profile Commands (Related to TACACS+)

### Configure Local Profiles
```
profile "<profile-name>"
default-action {deny-all | permit-all | none}
entry <entry-id>
match "<command-string>"
action {permit | deny}
```

**Examples:**
```
profile "limited"
    default-action deny-all
    entry 10
        match "show router route-table"
        action permit
    exit
    entry 20
        match "show users"
        action permit
    exit
    entry 30
        match "show system security user"
        action permit
    exit
    entry 40
        match "logout"
        action permit
    exit
exit
```

---

## 12. Complete Configuration Examples

### Basic TACACS+ Authentication Configuration
```
configure system security tacplus
    timeout 5
    server 1 address 10.10.0.5 secret "test1"
    server 2 address 10.10.0.6 secret "test2"
    no shutdown
exit
```

### TACACS+ with Authorization
```
configure system security tacplus
    authorization
    timeout 5
    server 1 address 10.10.0.5 secret "test1"
    server 2 address 10.10.0.6 secret "test2"
    no shutdown
exit
```

### TACACS+ with Accounting
```
configure system security tacplus
    accounting
    authorization
    timeout 5
    server 1 address 10.10.0.5 secret "test1"
    server 2 address 10.10.0.6 secret "test2"
    no shutdown
exit
```

### Full TACACS+ Configuration with Privilege Level Mapping
```
configure system security
    profile "limited"
        default-action deny-all
        entry 10
            match "show router route-table"
            action permit
        exit
        entry 20
            match "show users"
            action permit
        exit
        entry 30
            match "show system security user"
            action permit
        exit
        entry 40
            match "logout"
            action permit
        exit
    exit
    password
        authentication-order tacplus local exit-on-reject
        no health-check
    exit
    tacplus
        authorization use-priv-lvl
        priv-lvl-map
            priv-lvl 1 "limited"
            priv-lvl 15 "administrative"
        exit
        timeout 5
        server 1 address 192.168.1.47 secret "tac_secret" hash2
        no shutdown
    exit
exit
```

---

## 13. Show/Debug Commands for TACACS+

### Show Commands
```
show system security tacplus
show system security authentication
show system security password
show users
```

### Debug Commands
```
debug tacplus
debug security tacplus
clear tacplus
```

---

## 14. MD-CLI Format (Newer SR OS Versions)

For newer SR OS versions using MD-CLI flat format:

```
/configure system security tacplus server 1 address 192.168.1.47
/configure system security tacplus server 1 secret "tac_secret"
/configure system security tacplus timeout 5
/configure system security tacplus authorization admin-state enable
/configure system security tacplus priv-lvl-map priv-lvl 1 profile "limited"
/configure system security tacplus priv-lvl-map priv-lvl 15 profile "administrative"
/configure system security password authentication-order [tacplus local]
```

---

## 15. TACACS+ Command Authorization Format

When TACACS+ authorization is enabled without `use-priv-lvl`, the authorization request contains:
- `cmd`: First word of the CLI command
- `cmd-arg`: All following words (quoted values are expanded)

**Example Authorization Requests:**
```
cmd="show" cmd-arg="router route-table"
cmd="configure" cmd-arg="router isis"
cmd="admin" cmd-arg="save"
```

---

## Notes for Detection Engineering

1. **Authentication Events**: Look for login attempts via TACACS+ in security logs
2. **Authorization Events**: Each CLI command may generate a TACACS+ authorization request
3. **Accounting Events**: Track command execution with start/stop records
4. **Failed Attempts**: Monitor for authentication failures and lockouts
5. **Server Unreachable**: Monitor for TACACS+ server connectivity issues
6. **Privilege Escalation**: Watch for `enable-admin` usage and priv-lvl changes

---

## Source Documentation URLs

The commands in this document were extracted from the following Nokia documentation sources:

### Primary Sources

1. **7750 SR OS System Management Guide - Security CLI Configuration**
   - https://documentation.nokia.com/html/0_add-h-f/93-0071-10-01/7750_SR_OS_System_Management_Guide/security_cli.html

2. **7750 SR OS System Management Guide - Security Overview**
   - https://documentation.nokia.com/html/0_add-h-f/93-0071-10-01/7750_SR_OS_System_Management_Guide/security.html

3. **7750 SR OS System Management Guide - Security Command Reference**
   - https://documentation.nokia.com/html/0_add-h-f/93-0071-HTML/7750_SR_OS_System_Management_Guide/security-CLI.html

4. **7705 SAR System Management Guide - TACACS+ Client Commands**
   - https://infocenter.nokia.com/public/7705SAR234R1A/topic/com.nokia.system-mgmt-guide/tacacsx-client-commands.html

5. **7750 SR OS - TACACS+ Authorization**
   - https://infocenter.nokia.com/public/7750SR222R1A/topic/com.nokia.System_Mgmt_Guide/tacacsplus-_aut-ai9exj5x90.html

### Additional References

6. **ThingNetwork.io - TACACS+ Authentication with Nokia Service Routers** (Community Guide with Working Examples)
   - https://www.thingnetwork.io/tacacs-authentication-with-nokia-service-routers/

7. **Nokia SR Linux - Securing Access (TACACS+ Section)**
   - https://documentation.nokia.com/srlinux/22-6/SR_Linux_Book_Files/Configuration_Basics_Guide/configb-security.html

8. **Nokia SROS Peering Configuration (GitHub - AAA Section)**
   - https://github.com/sajusal/sros-peering

---

*Document compiled from Nokia SR OS System Management Guide and related documentation*
*Applicable to: Nokia 7750 SR, 7450 ESS, 7705 SAR, 7950 XRS series*
