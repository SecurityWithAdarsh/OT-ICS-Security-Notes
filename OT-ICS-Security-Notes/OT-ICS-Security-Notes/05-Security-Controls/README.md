# 05 - OT/ICS Security Controls

## Table of Contents
1. [Defense-in-Depth for OT](#defense-in-depth-for-ot)
2. [Compensating Controls](#compensating-controls)
3. [OT Endpoint Hardening](#ot-endpoint-hardening)
4. [Patch Management in OT](#patch-management-in-ot)
5. [Access Control](#access-control)
6. [Asset Inventory](#asset-inventory)
7. [Industrial Firewalls & DPI](#industrial-firewalls--dpi)
8. [Passive Monitoring / OT IDS](#passive-monitoring--ot-ids)
9. [Interview Q&A](#interview-qa)

---

## Defense-in-Depth for OT

OT security cannot rely on a single control (you cannot patch a PLC running proprietary firmware from 2005). Defense-in-depth layers multiple controls so that any single failure does not result in a breach.

```
Layer 1: Physical Security
├── Locked control rooms, server cabinets
├── Badge access to engineering workstations
├── USB port blocking (BIOS + physical)
└── CCTV at critical access points

Layer 2: Network Architecture
├── Purdue Model segmentation
├── IT/OT DMZ with dual firewalls
├── VLANs per function/criticality
└── Data diodes for historian feeds

Layer 3: Protocol Controls
├── Industrial DPI firewall (allowlist function codes)
├── Block unauthorized protocol directions
└── Detect anomalous Modbus/DNP3/OPC traffic

Layer 4: Endpoint Controls
├── Application whitelisting (no unauthorized software)
├── Disable unused services and ports
├── Host-based firewall rules
└── Local account controls

Layer 5: Monitoring & Detection
├── Passive OT IDS (Claroty, Dragos, Nozomi)
├── OT logs forwarded to SOC/SIEM
├── Baselines of normal traffic established
└── Alert on deviations from baseline

Layer 6: Access Control
├── MFA for all remote access
├── Privileged access management (PAM) for EWS
├── Session recording for vendor access
└── Least-privilege accounts

Layer 7: Procedures & Governance
├── Change management for any OT modification
├── Vendor access policy and procedures
├── Incident response plan (OT-specific)
└── Regular security assessments
```

---

## Compensating Controls

When standard security controls cannot be applied (due to legacy systems, operational constraints, vendor restrictions), compensating controls provide equivalent protection through other means.

| Standard Control | Why Not Applicable in OT | Compensating Control |
|---|---|---|
| **OS Patching** | PLC firmware cannot be patched mid-production; requires vendor approval | Network isolation; protocol allowlisting; monitoring for exploitation |
| **Antivirus** | Cannot install on PLC/RTU; may impact HMI performance | Application whitelisting; network-layer detection |
| **Encryption** | Legacy protocols (Modbus) do not support encryption | Network segregation; encrypted overlay (IPSec) between zones |
| **MFA** | HMI operator login cannot use MFA without slowing response time | Physical access controls; session activity monitoring |
| **Password complexity** | Shared operator accounts on HMI | Restrict physical access; log all HMI sessions |
| **Vulnerability scanning** | Active scanners can crash PLCs | Passive traffic analysis; vendor security advisories |
| **EDR** | Not supported on Windows CE/XP HMIs | Integrity monitoring; allowlisting; network isolation |

---

## OT Endpoint Hardening

### Engineering Workstation (EWS) — Highest Priority
The EWS is the crown jewel of OT networks — it can reprogram PLCs. Must be hardened aggressively.

```
EWS Hardening Checklist:
[ ] Not joined to corporate Active Directory domain
[ ] Standalone authentication or separate OT domain
[ ] Application whitelisting (only TIA Portal, engineering tools allowed)
[ ] USB disabled in BIOS + BIOS password set
[ ] No internet access; proxy or data diode for software updates
[ ] Dedicated non-admin account for daily use; admin only for changes
[ ] Full disk encryption (BitLocker)
[ ] Screen lock on inactivity (5 minutes)
[ ] All sessions logged to SIEM via syslog
[ ] Physical location in locked room with access log
```

### HMI Hardening
```
[ ] Remove all unnecessary software (games, browsers, media players)
[ ] Disable Windows services not required (Remote Registry, Telnet, FTP)
[ ] Enable Windows Firewall with restrictive rules
[ ] Disable USB (if not required for operations)
[ ] Application whitelisting (Wonderware, SCADA app only)
[ ] Unique local accounts per operator role
[ ] Automatic logout after session
[ ] OS kept on latest supported version (upgrade if EOL)
[ ] Backup HMI configuration before any change
```

### PLC/RTU — Limited Hardening Options
```
Available Controls (vendor-dependent):
[ ] Enable PLC password protection (if supported by firmware)
[ ] Restrict programming port access to EWS IP only (if supported)
[ ] Disable unused communication ports/slots
[ ] Enable write protection / run/program mode key switch (physical)
[ ] Segment PLC on dedicated VLAN; block access from HMI VLAN except required ports
[ ] Monitor for firmware changes (hash baseline)
[ ] Disable web server interface if not required
```

### Operating System Considerations
| OS | Status | OT Context | Recommendation |
|---|---|---|---|
| Windows XP | EOL 2014 | Still common on HMIs | Strict network isolation; application whitelist; plan for upgrade |
| Windows 7 | EOL 2020 | Common on HMIs, historians | Isolate from any network; prioritize upgrade |
| Windows 10 | Supported | Modern HMIs | Standard hardening; keep patched |
| Windows CE | EOL | Embedded HMIs, PLCs | No options; network isolation is the only control |
| Linux (embedded) | Varies | RTUs, some PLCs | Vendor-specific; often cannot be modified |

---

## Patch Management in OT

Patch management in OT is fundamentally different from IT:

### OT Patching Constraints
1. **Vendor qualification:** Patches must be tested and approved by the OT vendor before deployment (applying an unqualified patch may void warranty and cause failure)
2. **Change control:** Every change requires formal approval, documentation, and rollback plan
3. **Production windows:** Can only patch during planned shutdowns (may be annual)
4. **Legacy OS:** Windows XP/CE systems may not have available patches
5. **Regression risk:** A patch may break the SCADA/HMI application compatibility

### OT Patch Management Process
```
1. IDENTIFY
   ├── Subscribe to vendor security advisories (Siemens ProductCERT, Schneider, Rockwell PSIRT)
   ├── Subscribe to ICS-CERT / CISA advisories
   └── Maintain asset inventory to know which advisories apply

2. ASSESS
   ├── Is the vulnerability exploitable from current network position?
   ├── Does the vendor have a patch available?
   ├── Has the vendor qualified the patch for our firmware/OS version?
   └── Risk-score: CVSS + OT context (safety, availability impact)

3. TEST (if test environment exists)
   ├── Apply patch in lab to identical hardware/software
   ├── Run acceptance tests: does SCADA application still function?
   └── Document results

4. PLAN
   ├── Schedule for next planned maintenance window
   ├── Prepare rollback procedure
   ├── Communicate to operations team
   └── Approve via change management

5. DEPLOY
   ├── Deploy during planned downtime
   ├── Verify system function after patch
   └── Document completion

6. ACCEPT RISK (if patching not possible)
   ├── Document formal risk acceptance
   ├── Implement compensating controls
   └── Review at next maintenance window
```

### Virtual Patching
When a patch cannot be applied, "virtual patching" via the network:
- Industrial firewall blocks traffic that would exploit the vulnerability
- Example: block inbound connections to vulnerable OPC DA DCOM port from all except authorized hosts
- Deep packet inspection rule blocks specific exploit patterns

---

## Access Control

### Principle of Least Privilege in OT
| Role | Required Access | What to Restrict |
|---|---|---|
| **Operator** | Read process data, acknowledge alarms, limited control | Cannot modify PLC programs or setpoints |
| **Senior Operator** | Above + change process setpoints | Cannot modify PLC programs |
| **Process Engineer** | Above + view but not modify PLC programs | Cannot deploy PLC changes |
| **Automation Engineer** | Full PLC programming on EWS | Access only during change window; session recorded |
| **Vendor/Contractor** | Only their specific equipment | Time-limited; via jump server; recorded |
| **OT Security** | Read/passive monitoring across all | Cannot modify process or configurations |

### Account Types
```
Shared accounts:    AVOID — no individual accountability
Operator accounts:  Role-based; per-shift or per-person
Service accounts:   Minimal permissions; no interactive login; passwords rotated
Admin accounts:     Never used for daily tasks; PAM controls; break-glass procedure
Vendor accounts:    Disabled by default; enabled only for approved session window
```

### Authentication in OT Reality
- Most PLCs: no authentication at all (network is the only control)
- HMIs: local Windows accounts; often shared operator login for speed
- SCADA servers: Windows domain or local; OT-specific credentials
- Engineering tools: Software license keys as a form of access control
- Modern OPC UA: X.509 certificates; username/password

---

## Asset Inventory

You cannot secure what you do not know exists. Asset inventory is foundational.

### OT Asset Inventory Categories
```
For each asset, record:
├── Asset ID / Tag
├── Asset type (PLC, HMI, RTU, Switch, Server)
├── Vendor / Model / Serial Number
├── Firmware / OS version
├── IP address + MAC address
├── Purdue level / Zone
├── Protocols in use (Modbus, OPC, PROFINET)
├── Communication peers (what does it talk to?)
├── Criticality (safety-critical, production-critical, non-critical)
├── Last firmware update date
├── Known vulnerabilities (CVEs)
└── Owner / responsible engineer
```

### Passive Discovery Methods
- **Passive network monitoring:** Claroty, Dragos, Nozomi identify assets from traffic
- **Flow analysis:** NetFlow from managed switches reveals communication pairs
- **SCADA configuration export:** HMI tag databases list all connected PLCs
- **Manual inventory:** Walk-down of panels with asset tags (still necessary for offline devices)

> **Why not active scanning?** Nmap or similar tools can crash PLCs, RTUs, and legacy HMIs by sending unexpected packets to proprietary protocol stacks. Always passive-first in OT.

---

## Industrial Firewalls & DPI

### Standard Firewall Limitations in OT
Standard firewalls can only filter by IP/port. In OT, the threat is legitimate-looking traffic on legitimate ports — e.g., a Modbus write command on port 502 looks the same as a read command to a standard firewall.

### Industrial DPI Firewall Capabilities
| Capability | Description |
|---|---|
| **Protocol decode** | Understands Modbus, DNP3, OPC, EtherNet/IP at application layer |
| **Function code allowlisting** | Allow FC 0x03 (read), block FC 0x10 (write) from untrusted sources |
| **Device allowlisting** | Only registered IP can communicate with a specific PLC |
| **Bidirectional control** | Block unexpected initiators (HMI→PLC OK; unknown IP→PLC NOT OK) |
| **Anomaly detection** | Alert on new devices, unusual register access patterns |

### Industrial Firewall Vendors
- **Tofino Security** (Honeywell) — SCADA firewall
- **Claroty SRA** — secure remote access with protocol awareness
- **Cisco Industrial Network Director** — ICS-aware network management
- **Fortinet FortiGate** — ICS/SCADA application profiles available
- **Cisco Firepower** with OT application signatures

### Example DPI Rules (Modbus)
```
Rule 1: Allow Modbus reads from authorized master only
  Source: 192.168.2.10 (SCADA Master)
  Destination: 192.168.1.0/24 (PLC network)
  Port: TCP 502
  Function Codes: 0x01, 0x02, 0x03, 0x04 (reads only)
  Action: PERMIT, LOG

Rule 2: Allow Modbus writes only from EWS during change window
  Source: 192.168.3.5 (EWS)
  Destination: 192.168.1.10 (specific PLC)
  Port: TCP 502
  Function Codes: 0x05, 0x06, 0x0F, 0x10 (writes)
  Time: 06:00-08:00 UTC (maintenance window only)
  Action: PERMIT, LOG, ALERT

Rule 3: Block all other Modbus
  Source: ANY
  Destination: 192.168.1.0/24
  Port: TCP 502
  Action: DENY, LOG, ALERT
```

---

## Passive Monitoring / OT IDS

### Why Passive Monitoring is the OT Security Foundation
In OT, you often cannot patch, cannot install agents, and cannot disrupt operations for security scans. Passive monitoring is the primary detection mechanism.

### How OT Passive IDS Works
```
[OT Network] ──SPAN Port──► [Monitoring Sensor] ──► [Detection Platform]
                                                        (Claroty, Dragos)
Traffic copy sent to sensor without affecting network. Zero operational risk.
```

### What OT IDS Detects
- New asset appearing on network (unapproved device)
- New communication pair (PLC talking to something it never talked to before)
- Anomalous function codes (write command from unexpected source)
- Protocol violations (malformed Modbus packet)
- Engineering activity outside change windows (TIA Portal connecting at 3 AM)
- Known malware signatures (Industroyer, Pipedream patterns)
- Vulnerability exploitation attempts

### Leading OT Security Platforms
| Vendor | Product | Key Strength |
|---|---|---|
| **Claroty** | Continuous Threat Detection (CTD) | Deep protocol support, IT/OT convergence |
| **Dragos** | WorldView + Platform | Threat intelligence, ICS-specific playbooks |
| **Nozomi Networks** | Guardian | AI-based anomaly detection, asset inventory |
| **Microsoft** | Defender for IoT (formerly CyberX) | Azure integration, enterprise scale |
| **Tenable** | OT Security (formerly Indegy) | Vulnerability focus, risk scoring |

### Building Your Own (Open Source)
- **Zeek** (formerly Bro) with ICS protocol parsers (Modbus, DNP3, EtherNet/IP plugins)
- **Snort/Suricata** with ICS rules (Emerging Threats ICS ruleset)
- **Wireshark** for manual analysis
- **GrassMarlin** — CISA passive ICS network mapping tool (open source)
- **Malcolm** — network traffic analysis framework (CISA/Idaho National Lab)

---

## Interview Q&A

**Q: What is application whitelisting and why is it valuable in OT?**
> Application whitelisting only allows pre-approved executables to run on a system, blocking everything else by default. In OT, HMIs and EWS run a small, fixed set of software (Wonderware, TIA Portal, etc.) that rarely changes. Whitelisting means that even if malware reaches the endpoint via USB or network, it cannot execute. Tools like McAfee Application Control (now Trellix) are commonly used for legacy OT endpoints that can't run full EDR.

**Q: How do you approach patch management in an OT environment where you can't take systems offline?**
> OT patch management is risk-based. I subscribe to vendor security advisories (Siemens ProductCERT, Schneider PSIRT, ICS-CERT) and assess each vulnerability against our specific environment — can the attacker reach the vulnerable service from their network position? Is the vendor patch qualified for our firmware version? For patches that can't be applied immediately, I implement compensating controls: block the vulnerable service at the network layer (virtual patching), increase monitoring, and schedule deployment at the next planned maintenance window. All unpatched vulnerabilities are formally risk-accepted and documented.

**Q: What does OT passive monitoring detect that a traditional SIEM misses?**
> Traditional SIEMs are built around log data from IT assets — firewalls, endpoints, Active Directory. Most OT devices (PLCs, RTUs, older HMIs) produce no logs whatsoever. OT passive monitoring observes network traffic directly, building a behavioral baseline of which devices talk to each other, which protocols they use, and which function codes appear. It detects: new device appearing on the network, engineering tool connecting to a PLC at 3 AM, a Modbus write command from an unexpected source — all invisible to a log-based SIEM.
