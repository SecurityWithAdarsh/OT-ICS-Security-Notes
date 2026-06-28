# 03 - OT/ICS Architecture & Network Segmentation

## Table of Contents
1. [Purdue Reference Model](#purdue-reference-model)
2. [IT/OT DMZ Design](#itot-dmz-design)
3. [Network Segmentation Principles](#network-segmentation-principles)
4. [Unidirectional Gateways & Data Diodes](#unidirectional-gateways--data-diodes)
5. [Remote Access Architecture](#remote-access-architecture)
6. [Common Architecture Weaknesses](#common-architecture-weaknesses)
7. [Secure Architecture Checklist](#secure-architecture-checklist)
8. [Interview Q&A](#interview-qa)

---

## Purdue Reference Model

The Purdue Enterprise Reference Architecture (PERA), also called the Purdue Model, is the foundational framework for structuring ICS networks into hierarchical levels with controlled communication between them.

```
╔══════════════════════════════════════════════════════╗
║  LEVEL 4 — Enterprise Network (IT)                   ║
║  ERP, email, business apps, corporate users          ║
╠══════════════════════════════════════════════════════╣
║             IT/OT DMZ (Firewall)                     ║
╠══════════════════════════════════════════════════════╣
║  LEVEL 3 — Site Operations / Manufacturing Zone      ║
║  Historian, SCADA Servers, Engineering Workstations, ║
║  Patch Management Server, Remote Access Gateway      ║
╠══════════════════════════════════════════════════════╣
║             Cell/Area Zone Firewall                  ║
╠══════════════════════════════════════════════════════╣
║  LEVEL 2 — Supervisory Control                       ║
║  HMIs, Operator Workstations, Alarm Management,      ║
║  Batch Management, DCS Engineering Stations          ║
╠══════════════════════════════════════════════════════╣
║             Process Network Switch                   ║
╠══════════════════════════════════════════════════════╣
║  LEVEL 1 — Basic Process Control                     ║
║  PLCs, RTUs, DCS Field Controllers, Safety Systems   ║
╠══════════════════════════════════════════════════════╣
║             Field Device Bus (Serial/Industrial ETH) ║
╠══════════════════════════════════════════════════════╣
║  LEVEL 0 — Process / Field Layer                     ║
║  Sensors, Transmitters, Actuators, Valves,           ║
║  Motors, Variable Speed Drives                       ║
╚══════════════════════════════════════════════════════╝
```

### Level Responsibilities

| Level | Name | Key Assets | Typical Protocols |
|---|---|---|---|
| 0 | Field | Sensors, actuators, valves | Analog 4-20mA, HART, fieldbus |
| 1 | Basic Control | PLCs, RTUs | Modbus RTU, PROFIBUS, serial |
| 2 | Supervisory | HMIs, DCS stations | Modbus TCP, OPC DA, PROFINET |
| 3 | Site Operations | Historians, SCADA, EWS | OPC DA/UA, SQL, RDP |
| 3.5 | IT/OT DMZ | Firewalls, jump servers, historians | Various (controlled) |
| 4 | Enterprise | ERP, email, IT systems | HTTP/S, SMTP, Active Directory |

### Key Purdue Security Principle
**No Level should communicate directly with a Level more than one step away without passing through a DMZ or firewall.** A Level 0 device should never directly communicate with Level 4 enterprise systems.

> **Field Note (Aarti Industries):** The plant had a relatively good Purdue-aligned segmentation. Level 1 PLCs communicated only with Level 2 HMIs on a dedicated control VLAN. Level 3 historian pulled data from Level 2 via a managed switch with ACLs. Corporate IT was separated by a physical firewall. However, there was no formal DMZ — the historian sat at the edge of Level 3 with direct connectivity to both the control network below and corporate above.

---

## IT/OT DMZ Design

The DMZ (Level 3.5) is a critical buffer zone between enterprise IT and the OT environment. All cross-boundary communication must pass through it.

### DMZ Architecture Patterns

**Pattern 1: Dual-Firewall DMZ (Recommended)**
```
[Corporate IT]
      │
  [Firewall A]  ← IT-facing ruleset
      │
  [DMZ Zone]
  ├── Data Historian (OT read replica)
  ├── Jump Server / Bastion Host (for remote access)
  ├── Patch Management Server
  ├── File Transfer Server (for OT updates)
  └── Remote Access Gateway (vendor VPN)
      │
  [Firewall B]  ← OT-facing ruleset (more restrictive)
      │
[OT Control Network]
```

**Pattern 2: Unidirectional Gateway (Highest Security)**
```
[OT Control Network]
      │
  [Data Diode] ── data flows one way only (OT → IT)
      │
[IT / Enterprise]
```

### DMZ Servers and Their Purpose
| Server | Role | Security Consideration |
|---|---|---|
| **Historian (DMZ copy)** | OT data available to IT without direct OT access | Should receive data via diode/push only |
| **Jump Server** | Only authorized path to reach OT network | Must log all sessions; MFA required |
| **Patch Server** | Stage and test OT patches before deployment | Critical — compromising this = OT supply chain attack |
| **Remote Access GW** | Vendor/engineer remote sessions | Session recording; least-privilege network access |
| **AV/Signature Update** | Push AV updates to OT endpoints | OT-specific AV; tested before deployment |

---

## Network Segmentation Principles

### Defense in Depth for OT

```
1. Physical Security      ← Lock the control room; badge access to EWS
2. Network Segmentation   ← VLANs, firewalls between Purdue levels
3. IT/OT DMZ              ← Controlled transfer zone
4. Endpoint Hardening     ← Disable USB, whitelist applications
5. Protocol Filtering     ← DPI firewall; allowlist Modbus function codes
6. Passive Monitoring     ← IDS for OT (Claroty, Dragos, Nozomi)
7. Access Control         ← MFA for jump server; shared accounts discouraged
```

### VLAN Design for OT
```
VLAN 10: Corporate IT
VLAN 20: DMZ (historians, jump servers)
VLAN 30: Level 3 OT (SCADA servers, EWS)
VLAN 40: Level 2 HMI
VLAN 50: Level 1 PLC (most restricted)
VLAN 60: Safety Systems (SIS — physically separate preferred)
```

### Firewall Ruleset Philosophy for OT
| Rule Type | IT Firewalls | OT Firewalls |
|---|---|---|
| **Default policy** | Default deny | Default deny (even stricter) |
| **Allowed traffic** | Defined by business need | Explicitly defined operational flows only |
| **Changes** | Change management process | Require OT engineer + security approval |
| **Rule review** | Quarterly | Before and after any outage |
| **Logging** | Standard | All allows AND denies logged |

### IEC 62443 Zone and Conduit Model
IEC 62443 formalizes segmentation into:
- **Zones:** Groups of OT assets with similar security requirements and risk
- **Conduits:** Communication paths between zones (each must be secured and justified)

Every inter-zone communication flow must be documented as a conduit with a defined security level target.

---

## Unidirectional Gateways & Data Diodes

### What is a Data Diode?
A data diode is a hardware device that enforces **one-way data flow** at the physical layer. It uses fiber optic hardware where only the TX (transmit) wire is connected — making reverse communication physically impossible.

```
[OT Control Network] ──TX──► [Data Diode Hardware] ──► [IT / Historian]
                                   (no RX path)
No traffic can flow OT ← IT regardless of software configuration
```

### Use Cases
- Sending Historian data from OT to IT without creating a bidirectional path
- Delivering log data to SOC without any return path into OT
- Firmware distribution (separate unidirectional gateway in reverse direction)

### Vendors
- **Waterfall Security Solutions** (Unidirectional Security Gateway)
- **Owl Cyber Defense** (OPDS data diode)
- **Genua** (Genugate)

### Limitation
Data diodes prevent bidirectional communication, which means:
- No OPC poll-response (polling must be replaced with push architecture)
- No acknowledgement-based protocols (need protocol replication software)
- Vendors provide software that converts bidirectional protocols to push on the OT side

---

## Remote Access Architecture

Remote access is one of the **highest-risk vectors** in OT security. Vendor remote maintenance sessions have been the entry point in multiple major OT incidents.

### Secure Remote Access Architecture
```
[Vendor / Engineer]
       │
  [Internet / WAN]
       │
  [Remote Access Gateway in DMZ]
  - MFA enforced
  - Session recording (full keylog + screen capture)
  - Time-limited access windows
  - Least-privilege network ACLs (only to specific PLC, not whole network)
       │
  [Jump Server in DMZ]
       │
  [Target OT Asset]
```

### Requirements for Secure Vendor Access
- [ ] Dedicated VPN account per vendor (no shared credentials)
- [ ] MFA on remote access gateway
- [ ] Session recording and review capability
- [ ] Time-limited access: open session on request, close after maintenance
- [ ] Network ACLs: vendor can only reach their specific equipment
- [ ] Vendor's machine checked for malware before session allowed
- [ ] Session monitored by OT security team in real-time

> **The Oldsmar Attack (2021):** TeamViewer was used for legitimate remote access to a water treatment plant. An attacker used old credentials (or credential theft) to access the HMI and changed sodium hydroxide setpoints from 111 ppm to 11,100 ppm. An operator noticed the cursor moving and reversed the change. The failure: TeamViewer directly accessible from the internet with no MFA, no session recording, and no separate DMZ.

---

## Common Architecture Weaknesses

| Weakness | Description | Example |
|---|---|---|
| **Flat OT network** | All OT assets on same VLAN/subnet | Worm spreads from one PLC to all HMIs |
| **No IT/OT DMZ** | Direct connectivity between IT and OT | Ransomware spreads from IT to SCADA |
| **VPN terminating in OT** | Vendor VPN endpoint inside control network | Vendor compromise = full OT access |
| **EWS on corporate domain** | Engineering workstation joined to AD | IT credential attack reaches PLC programmer |
| **USB not controlled** | Removable media used for updates | Stuxnet-style USB infection |
| **Historian dual-homed** | Historian has NICs on both IT and OT | Pivot from IT to OT via historian |
| **OT systems on internet** | SCADA/HMI accessible via Shodan | Direct attack without corporate network access |
| **No monitoring in OT** | Zero visibility into Level 1/2 traffic | Attacker dwells undetected for months |

### Shodan Exposure
Search `port:502` or `port:102` on Shodan to find internet-exposed Modbus/S7comm devices. Thousands exist globally. Direct internet exposure is an extreme architectural failure.

---

## Secure Architecture Checklist

```
NETWORK SEGMENTATION
[ ] Purdue Model levels implemented with firewalls between each level
[ ] IT/OT DMZ established with dual firewall architecture
[ ] OT VLANs separated by function (HMI, PLC, SIS, EWS, Historian)
[ ] No direct routing between IT and OT control network

DATA TRANSFER
[ ] All IT↔OT data transfer via DMZ intermediary
[ ] Unidirectional gateway or data diode implemented for historian feeds
[ ] File transfer to OT done via staged scanning server in DMZ

REMOTE ACCESS
[ ] All remote access enters via DMZ remote access gateway
[ ] MFA enforced on all remote access
[ ] Session recording enabled and reviewed
[ ] Vendor accounts are time-limited and least-privilege

MONITORING
[ ] Passive OT monitoring sensor deployed in Level 1/2
[ ] OT security alerts forwarded to SOC via DMZ
[ ] Baseline of normal OT traffic established

PHYSICAL
[ ] Level 1 network physically restricted (locked panels)
[ ] EWS in controlled area with badge access
[ ] USB/removable media blocked or controlled
```

---

## Interview Q&A

**Q: Describe the Purdue Reference Model and why it matters for OT security.**
> The Purdue Model organizes ICS networks into levels from Level 0 (physical field devices) through Level 4 (enterprise IT). Security principle: each level should only communicate with adjacent levels, and all cross-level traffic passes through firewalls or DMZs. This segmentation prevents an attacker who compromises an IT system from directly reaching PLCs, and limits lateral movement within OT. Without Purdue-aligned segmentation, a ransomware infection at Level 4 can directly reach Level 1 controllers.

**Q: What is an IT/OT DMZ and what goes in it?**
> The IT/OT DMZ (Level 3.5) is a buffer network between corporate IT and the OT control network. It hosts servers that must communicate with both sides — data historians (as data relay, not direct access), jump servers for authorized OT access, remote access gateways for vendors, and patch management servers. The key principle is that no direct connection exists between IT and OT — all communication routes through the DMZ, which can inspect, log, and control flows in both directions.

**Q: Why are data diodes used in high-security OT environments?**
> Data diodes enforce one-way data flow at the physical layer — fiber optic hardware with only TX connected, making reverse communication physically impossible regardless of software misconfiguration. They're used when an organization needs to share OT data with IT (for historian, analytics, SOC monitoring) but cannot accept any risk of a return path into the OT network. Even if the IT-side system is compromised, it cannot send any data back into OT.

**Q: What was the Oldsmar water plant attack and what architectural control would have prevented it?**
> In 2021, an attacker used TeamViewer to access a Florida water plant's HMI and raised sodium hydroxide to dangerous levels. An operator noticed and reversed it. The root cause was TeamViewer accessible directly from the internet with no MFA and no session monitoring. A proper remote access architecture — TeamViewer behind a VPN with MFA, sessions routed through a DMZ jump server with recording — would have either prevented access entirely or detected it immediately.
