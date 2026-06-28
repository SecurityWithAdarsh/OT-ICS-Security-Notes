# 04 - OT/ICS Threats and Attack Vectors

## Table of Contents
1. [Threat Landscape Overview](#threat-landscape-overview)
2. [MITRE ATT&CK for ICS](#mitre-attck-for-ics)
3. [Attack Kill Chain in OT](#attack-kill-chain-in-ot)
4. [OT-Specific Malware Families](#ot-specific-malware-families)
5. [Common Attack Vectors](#common-attack-vectors)
6. [Threat Actor Categories](#threat-actor-categories)
7. [Interview Q&A](#interview-qa)

---

## Threat Landscape Overview

OT/ICS systems face a unique threat landscape because attacks can have **physical consequences** — equipment damage, production loss, environmental release, or harm to people.

### Impact Categories
| Impact | Example |
|---|---|
| **Safety** | Stuxnet destroying centrifuges; TRITON targeting safety systems |
| **Environmental** | Oldsmar water attack; Colonial Pipeline disruption |
| **Financial** | Production downtime; equipment replacement (tens of millions) |
| **Reputational** | Disclosure of critical infrastructure breach |
| **Cascading** | Ukraine power grid: 250,000 customers without power |

### OT vs IT Threat Differences
| Dimension | IT Threats | OT Threats |
|---|---|---|
| **Primary goal** | Data exfiltration, encryption for ransom | Process disruption, physical damage, espionage |
| **Dwell time** | Weeks to months | Months to years (for sophisticated actors) |
| **Attack difficulty** | Broadly accessible TTPs | Requires ICS domain knowledge |
| **Detection** | Mature tooling | Limited visibility; passive monitoring only |
| **Recovery** | Restore from backup | May require physical equipment replacement |

---

## MITRE ATT&CK for ICS

MITRE ATT&CK for ICS documents adversary tactics and techniques specific to industrial control systems. 14 tactic categories:

### Tactic Overview

| Tactic | ID | Description | Example Technique |
|---|---|---|---|
| **Initial Access** | TA0108 | Gain foothold in ICS environment | Spearphishing, Internet-Accessible Device |
| **Execution** | TA0104 | Run adversary code on OT system | Scripting, Native API, Compiled Python |
| **Persistence** | TA0110 | Maintain foothold in ICS | Modify PLC, Hijack Control Software |
| **Privilege Escalation** | TA0111 | Gain higher privileges | Exploitation of vulnerability on EWS |
| **Evasion** | TA0103 | Avoid detection | Masquerade as Legitimate Tool, Rootkit |
| **Discovery** | TA0102 | Map the ICS environment | Remote System Discovery, Network Sniffing |
| **Lateral Movement** | TA0109 | Move between systems | Default Credentials, Remote Services |
| **Collection** | TA0100 | Gather data from ICS | Monitor Process State, I/O Image |
| **C2** | TA0101 | Maintain communication | Standard Application Layer Protocol |
| **Inhibit Response** | TA0107 | Prevent safety/detection response | Block Reporting, Disable Safety Systems |
| **Impair Process Control** | TA0106 | Disrupt control of process | Unauthorized Command Message, Modify Parameters |
| **Impact** | TA0105 | Cause physical damage or disruption | Damage Physical Properties, Loss of View |

### Key ICS Techniques

**T0862 — Unauthorized Command Message**
> Sending protocol commands (Modbus FC 0x10, DNP3 Direct Operate) directly to field devices without going through legitimate control software. The technique used in almost every OT attack.

**T0857 — System Firmware**
> Modifying PLC firmware to implant persistent malicious logic. Used by Stuxnet to alter centrifuge speed while reporting normal values.

**T0855 — Unauthorized Command Message (Safety System)**
> Specifically targeting SIS/ESD systems to prevent them from triggering safety shutdowns. Used by TRITON/TRISIS.

**T0836 — Modify Parameter**
> Changing setpoints, thresholds, or configurations via legitimate engineering protocols. Oldsmar attacker used this via HMI.

**T0816 — Loss of View**
> Manipulating sensor data or HMI displays so operators cannot see what is actually happening in the process. Stuxnet showed false normal readings.

**T0813 — Denial of View**
> Blocking legitimate operator view of process — disabling alarms, crashing HMI.

---

## Attack Kill Chain in OT

Sophisticated OT attacks typically follow a multi-stage progression:

```
STAGE 1: IT Compromise
├── Spearphishing employee
├── Exploit internet-facing system (VPN, email)
├── Supply chain compromise (vendor software update)
└── Watering hole on ICS vendor site

         ↓

STAGE 2: Establish Foothold in IT/Level 3
├── Lateral movement in corporate network
├── Credential harvesting (mimikatz)
├── Establish persistence (RAT, scheduled task)
└── Identify IT/OT boundary

         ↓

STAGE 3: Cross IT/OT Boundary
├── Compromise jump server or historian
├── Abuse legitimate remote access (TeamViewer, RDP)
├── USB drop / insider access
└── Exploit dual-homed system (historian with both NICs)

         ↓

STAGE 4: OT Reconnaissance
├── Passive traffic sniffing (learn protocols in use)
├── Enumerate HMIs, SCADA servers, PLCs
├── Map process: what does each controller do?
├── Read PLC programs (TIA Portal, RSLogix 5000)
└── Understand normal operating parameters

         ↓

STAGE 5: Develop OT Capability
├── Understand target process deeply
├── Develop or adapt ICS-specific payloads
├── Test in lab environment (if nation-state)
└── Identify attack timing (e.g., disable safety first)

         ↓

STAGE 6: Execute Attack
├── Disable/manipulate SIS (TRITON model)
├── Modify PLC logic or setpoints
├── Destroy historian/SCADA for delayed detection
└── Trigger physical process upset

         ↓

STAGE 7: Cover Tracks / Persist
├── Delete logs from SCADA/HMI
├── Maintain persistent access for follow-on
└── Blend in with normal maintenance traffic
```

---

## OT-Specific Malware Families

### 1. Stuxnet (2010)
- **Target:** Iranian Natanz nuclear facility (Siemens S7-315/417 PLCs)
- **Goal:** Destroy uranium enrichment centrifuges while hiding from operators
- **Mechanism:**
  - Spread via USB (exploited 4 Windows zero-days)
  - Installed Siemens S7 PLC rootkit via WinCC/Step7 OPC server
  - Modified centrifuge speed profiles while reporting normal readings to HMI
  - Disabled SIS so safety systems couldn't halt the damage
- **Impact:** ~1,000 centrifuges destroyed over months
- **MITRE:** T0857 (System Firmware), T0855 (Inhibit Response Function), T0816 (Loss of View)

### 2. TRITON / TRISIS (2017)
- **Target:** Petro Rabigh petrochemical plant, Saudi Arabia (Schneider Electric Triconex SIS)
- **Goal:** Disable Safety Instrumented System to allow physical damage without protection
- **Mechanism:**
  - Compromised EWS in OT network
  - Deployed TRITON framework targeting Triconex TSCP (Triconex Communication Protocol)
  - Attempted to reprogram SIS logic; a bug caused SIS to fail safe and halt production
  - Attack discovered accidentally because it caused an unplanned shutdown
- **Impact:** Near-miss with catastrophic physical event
- **Significance:** First publicly known malware specifically targeting a SIS
- **MITRE:** T0855, T0857, T0800

### 3. Industroyer / CrashOverride (2016)
- **Target:** Ukrainian power grid (Ukrenergo)
- **Goal:** Cause power outage; damage substation equipment
- **Mechanism:**
  - Modular framework with protocol modules: IEC 61850, IEC 104, DNP3, OPC DA
  - Automatically opened circuit breakers using native ICS protocols
  - Wiper component attacked protective relays to cause physical damage
  - Launched denial-of-service against serial-to-Ethernet converters
- **Impact:** ~225,000 customers lost power for 1–6 hours
- **Significance:** First malware that natively spoke ICS protocols to attack grid

### 4. BlackEnergy (2015) — Ukraine Power Grid (first attack)
- **Target:** Ukrainian distribution companies
- **Mechanism:**
  - BlackEnergy malware via spearphishing
  - Operators locked out of SCADA (passwords changed, UPS firmware wiped)
  - Attackers manually opened breakers via HMI
  - Phone systems overwhelmed to prevent customers reporting outages
- **Impact:** ~225,000 customers; first confirmed cyber attack causing power outage

### 5. Pipedream / INCONTROLLER (2022)
- **Target:** Energy sector (US), discovered before deployment
- **Goal:** Attack PLCs from multiple vendors (Schneider, Omron) and CODESYS-based devices
- **Mechanism:**
  - TAGRUN: scans for and attacks Omron PLCs
  - MOUSEHOLE: OPC UA scanning tool
  - BADOMEN: Schneider Modicon PLC exploitation
  - EVILSCHOLAR: Schneider Electric device interaction
- **Significance:** Most sophisticated ICS attack framework discovered; cross-vendor capability

### 6. Colonial Pipeline (2021) — Note: IT Ransomware with OT Impact
- **Target:** Colonial Pipeline (IT billing system)
- **Mechanism:** DarkSide ransomware via compromised VPN credentials (no MFA)
- **OT Impact:** Colonial *voluntarily* shut down OT pipeline operations out of caution, not because OT was compromised
- **Impact:** East coast fuel shortage; $4.4M ransom paid
- **Key Lesson:** IT ransomware can cause OT operational impact even without directly attacking OT systems

---

## Common Attack Vectors

### 1. Spearphishing → IT → OT Lateral Movement
Most sophisticated OT attacks start with IT compromise and then pivot.
- OT vendor impersonation emails to plant engineers
- Malicious PDF attachments with ICS theme
- Watering hole attacks on ICS vendor websites

### 2. Internet-Exposed OT Systems
Shodan regularly indexes thousands of internet-exposed:
- Modbus TCP servers (port 502)
- Siemens S7 (port 102)
- DNP3 devices (port 20000)
- SCADA HMIs (web-based, port 80/443)
- VNC directly on engineering workstations

### 3. USB / Removable Media
- Air-gapped or poorly connected OT systems rely on USB for updates
- Stuxnet specifically targeted this vector
- Infected USB can introduce malware into completely air-gapped Level 1 networks
- Controls: disable USB in BIOS, use write-blockers, scan in designated kiosk

### 4. Vendor Remote Access
- Vendors need remote access for maintenance, diagnostics, updates
- Historically: TeamViewer, RDP directly exposed; no MFA; shared credentials
- Notable example: Oldsmar water plant

### 5. Supply Chain
- Malicious firmware update to PLC/RTU vendor
- Compromised engineering software (TIA Portal, RSLogix update)
- Malicious driver update for HMI hardware

### 6. Insider Threat
- Disgruntled former employee with retained access
- Maroochy Shire (Australia, 2000): former contractor used stolen radio equipment to release 800,000 liters of raw sewage by sending unauthorized DNP3-like commands to water treatment RTUs

---

## Threat Actor Categories

| Category | Motivation | Capability | OT Examples |
|---|---|---|---|
| **Nation-State** | Geopolitical, espionage, pre-positioning | Very high; custom ICS malware | Stuxnet (likely US/Israel), TRITON (Russia), Industroyer (Russia/Sandworm) |
| **Ransomware Groups** | Financial — ransom payment | Medium; mostly IT, occasional OT | DarkSide (Colonial), Cl0p (water/waste), Vice Society |
| **Hacktivists** | Political statement | Low — mostly defacement | Defaced ICS HMIs, DDoS against utilities |
| **Insiders** | Revenge, financial gain | High — authorized access | Maroochy Shire sewage attack, disgruntled operators |
| **Cybercriminals** | Financial | Medium — using off-shelf tools | Exploiting internet-exposed ICS for cryptomining, access brokering |

### Nation-State Groups Targeting OT
| Group | Country | Aliases | Known Targets |
|---|---|---|---|
| Sandworm | Russia | APT44, Voodoo Bear | Ukraine power grid, multiple industrial |
| APT40 | China | TEMP.Periscope | Maritime, engineering |
| Volt Typhoon | China | Bronze Silhouette | US critical infrastructure pre-positioning |
| Lazarus | North Korea | Hidden Cobra | Energy sector, financial |
| APT33 | Iran | Elfin | Aviation, energy, petrochemical |

---

## Interview Q&A

**Q: What is TRITON/TRISIS and why is it significant?**
> TRITON targeted a Schneider Electric Triconex Safety Instrumented System at a petrochemical plant in Saudi Arabia. It's the first publicly known malware specifically designed to attack a SIS — the last line of defense preventing a dangerous process from causing a physical catastrophe. By disabling the SIS before causing a process upset, attackers could cause physical damage without the safety system intervening. It was discovered accidentally when a bug in the malware caused the SIS to fail safe and trigger an unplanned shutdown.

**Q: Explain the Stuxnet attack and what made it technically sophisticated.**
> Stuxnet spread via USB drives exploiting four Windows zero-days. Once inside the Siemens Step7/WinCC environment, it installed a PLC rootkit that modified centrifuge speed profiles while simultaneously feeding the HMI false "normal" data so operators saw nothing wrong. It also disabled the Safety Instrumented System to prevent emergency shutdowns. The result was ~1,000 centrifuges physically destroyed over months. Its sophistication was unprecedented: multi-vector, multi-platform, with deep ICS domain knowledge about Siemens S7 internals and centrifuge physics.

**Q: What is MITRE ATT&CK for ICS and how is it different from enterprise ATT&CK?**
> ATT&CK for ICS extends the framework with OT-specific tactics and techniques. Key differences: it includes ICS-specific tactics like "Impair Process Control" and "Inhibit Response Function" that don't exist in enterprise ATT&CK. Techniques reference ICS protocols (Modbus, DNP3, OPC), ICS-specific software (TIA Portal, RSLogix), and ICS equipment (PLCs, RTUs, SIS). It also recognizes that impact in ICS extends beyond data to physical damage, safety events, and process disruption.

**Q: What attack vector was used in the Colonial Pipeline incident?**
> DarkSide ransomware group used a compromised VPN account with no multi-factor authentication to access Colonial Pipeline's IT network. The ransomware encrypted IT systems including billing. Importantly, the OT pipeline operations were not directly compromised — Colonial shut down OT operations proactively out of caution about potential OT spread. This illustrates that IT security failures can cause OT operational impact even without directly attacking OT systems.
