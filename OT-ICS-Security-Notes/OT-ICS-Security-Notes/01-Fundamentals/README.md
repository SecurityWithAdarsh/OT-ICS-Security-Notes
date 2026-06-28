# 01 - OT/ICS Fundamentals

## Table of Contents
1. [What is OT/ICS?](#what-is-otics)
2. [IT vs OT: Core Differences](#it-vs-ot-core-differences)
3. [CIA Triad Inversion in OT](#cia-triad-inversion-in-ot)
4. [Key Terminology](#key-terminology)
5. [OT Component Hierarchy](#ot-component-hierarchy)
6. [Common OT Environments](#common-ot-environments)
7. [Interview Q&A](#interview-qa)

---

## What is OT/ICS?

**Operational Technology (OT)** refers to hardware and software that monitors and controls physical processes, devices, and infrastructure. Unlike IT systems that process data, OT systems interact directly with the physical world.

**Industrial Control Systems (ICS)** is the umbrella term for systems used to control industrial processes:

| System Type | Full Name | Use Case |
|---|---|---|
| SCADA | Supervisory Control and Data Acquisition | Wide-area monitoring (pipelines, grid) |
| DCS | Distributed Control System | Continuous process control (chemical, refinery) |
| PLC | Programmable Logic Controller | Discrete/batch control (manufacturing, chemical) |
| SIS | Safety Instrumented System | Emergency shutdown, independent safety layer |
| RTU | Remote Terminal Unit | Remote field data collection → SCADA |

---

## IT vs OT: Core Differences

| Dimension | IT | OT |
|---|---|---|
| **Primary Goal** | Data confidentiality & integrity | Physical process availability & safety |
| **Uptime Requirement** | 99.9% acceptable | 99.999%+ critical; planned downtime only |
| **Patch Cycles** | Monthly/weekly | Yearly or never (qualification required) |
| **Protocols** | TCP/IP, HTTP, TLS | Modbus, OPC, DNP3, PROFINET |
| **Change Management** | Agile | Extremely rigid; vendor-approved only |
| **Lifespan** | 3–5 years | 15–30 years |
| **Encryption** | Standard | Often absent (legacy constraints) |
| **Authentication** | MFA, PKI | Often shared credentials or none |
| **Response to Incident** | Shut it down | Cannot shut down; safety first |
| **Testing** | QA environment standard | Test environment rare or absent |
| **Network Visibility** | SIEM, full logging | Often no logging capability at all |

> **Field Note (Aarti Industries):** Siemens S7-300 PLCs controlling chemical reactors ran firmware from 2009. Patching required a full production shutdown — a multi-day event needing management approval and Siemens engineers on-site. Security patches could not follow a standard cycle.

---

## CIA Triad Inversion in OT

In IT security: **Confidentiality → Integrity → Availability**

In OT/ICS (inverted): **Availability → Integrity → Confidentiality**

```
OT Priority Order:

1. AVAILABILITY     ← Reactor offline = financial loss + potential safety incident
2. INTEGRITY        ← Wrong sensor reading = wrong control decision = process upset
3. CONFIDENTIALITY  ← Data theft is bad, but not immediately life-threatening
```

### Practical Impact

| Scenario | IT Response | OT Response |
|---|---|---|
| Ransomware detected | Isolate & shut down system | Cannot shut down; implement containment workaround |
| Suspicious network scan | Block immediately | Must verify it's not a legitimate engineering tool first |
| Unpatched vulnerability | Emergency patch | Risk-assess; may accept risk rather than patch mid-run |
| Credential sharing detected | Force individual accounts | May need shared accounts for operational continuity |

---

## Key Terminology

| Term | Definition |
|---|---|
| **PLC** | Programmable Logic Controller — executes control logic (ladder logic, function block) to control field devices |
| **RTU** | Remote Terminal Unit — collects data from remote field sites, transmits to SCADA over WAN |
| **HMI** | Human-Machine Interface — operator screen showing real-time process status and control |
| **SCADA** | Supervisory Control and Data Acquisition — centralized monitoring and supervisory control |
| **DCS** | Distributed Control System — process control distributed across multiple controllers |
| **SIS** | Safety Instrumented System — independent layer that triggers emergency shutdown |
| **EWS** | Engineering Workstation — used to program PLCs/DCS; highest-value target for attackers |
| **OPC** | OLE for Process Control — middleware enabling vendor-neutral HMI↔PLC communication |
| **Historian** | Time-series database storing process data (e.g., AVEVA OSIsoft PI, Wonderware Historian) |
| **Conduit** | Communication path between two security zones (IEC 62443 term) |
| **Zone** | Logical grouping of OT assets with similar security requirements (IEC 62443 term) |
| **SIL** | Safety Integrity Level — rating for SIS reliability (SIL 1 = lowest, SIL 4 = highest) |
| **ESD** | Emergency Shutdown — automatic process shutdown triggered by SIS |
| **HAZOP** | Hazard and Operability Study — systematic process safety risk identification method |
| **P&ID** | Piping and Instrumentation Diagram — shows physical layout and connections of process |
| **Ladder Logic** | PLC programming language that resembles electrical relay diagrams |
| **Tag** | Named reference to a process variable (e.g., TIC-101 = Temperature Indicator Controller) |

---

## OT Component Hierarchy

```
┌─────────────────────────────────────────────────┐
│  Level 4: Enterprise Network                     │
│  ERP systems, business applications, IT users    │
├─────────────────────────────────────────────────┤
│             [IT/OT DMZ — Firewall / Data Diode]  │
├─────────────────────────────────────────────────┤
│  Level 3: Site Operations / Control Center       │
│  Historian, SCADA Server, Engineering WS, Patch  │
│  management server, remote access gateway        │
├─────────────────────────────────────────────────┤
│             [Firewall / VLAN Segmentation]        │
├─────────────────────────────────────────────────┤
│  Level 2: Supervisory Control                    │
│  HMIs, Operator Workstations, Alarm Management,  │
│  DCS Controller stations                         │
├─────────────────────────────────────────────────┤
│             [Managed Switch / Firewall]           │
├─────────────────────────────────────────────────┤
│  Level 1: Basic Process Control                  │
│  PLCs, RTUs, DCS Field Controllers               │
├─────────────────────────────────────────────────┤
│             [Serial / Industrial Ethernet]        │
├─────────────────────────────────────────────────┤
│  Level 0: Field / Process Layer                  │
│  Sensors, Transmitters, Actuators, Valves,       │
│  Motors, Drives                                  │
└─────────────────────────────────────────────────┘
```

This is the **Purdue Reference Model** — see [03-Architecture](../03-Architecture/) for deep dive.

---

## Common OT Environments by Sector

| Sector | PLCs/DCS | SCADA | Key Protocol | Primary Risk |
|---|---|---|---|---|
| Chemical | Siemens S7, ABB 800xA | Wonderware, iFIX | Modbus, PROFINET | Runaway reaction, toxic release |
| Power Grid | GE, Siemens, ABB relays | GE eDNA, OSIsoft PI | DNP3, IEC 61850 | Cascading blackout |
| Oil & Gas | Emerson DeltaV, Honeywell | Aspen, Wonderware | Modbus, OPC | Pipeline rupture, explosion |
| Water | Allen-Bradley PLCs | Various SCADA | Modbus, DNP3 | Chemical dosing manipulation |
| Manufacturing | Rockwell, Siemens | FactoryTalk, WinCC | PROFINET, EtherNet/IP | Production disruption, safety |

---

## Interview Q&A

**Q: What is the biggest security difference between IT and OT environments?**
> In IT, we can take systems offline to patch or respond to incidents. In OT, a PLC controlling a chemical reactor or power turbine cannot be shut down — the physical process continues regardless. A loss of control can mean safety incidents, equipment damage, or loss of life. This forces OT security to prioritize availability over confidentiality and rely on compensating controls like network segmentation and passive monitoring rather than patching.

**Q: What is a Safety Instrumented System and why is it architecturally separated?**
> A SIS monitors process variables and automatically brings the plant to a safe state when dangerous thresholds are exceeded — for example, triggering an Emergency Shutdown if reactor pressure exceeds safe limits. It must be architecturally independent from the DCS/PLC running normal process control, so that if the primary control system fails or is compromised, the SIS can still intervene. Stuxnet notably tried to disable the SIS on Iranian centrifuges to prevent safety shutdowns during its manipulation.

**Q: Why can't you just apply standard IT security practices to OT?**
> OT environments have 15–30 year asset lifespans, proprietary RTOS with no support for modern security features, vendor qualification requirements that prevent unauthorized patching, and zero-tolerance for availability impacts. Standard IT tools like Nmap can crash PLCs with unexpected probe packets. Security must be passive-first, availability-first, with compensating controls rather than direct hardening.
