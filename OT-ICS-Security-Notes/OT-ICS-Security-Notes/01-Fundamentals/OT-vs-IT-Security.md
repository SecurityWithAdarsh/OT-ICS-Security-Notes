# OT vs IT Security — The Core Differences

> Understanding this distinction is the foundation of everything in ICS/OT security. IT and OT look similar on the surface (networks, endpoints, protocols) but have fundamentally different priorities, constraints, and failure modes.

---

## The CIA Triad — Flipped

In IT security, the priority order is:

```
Confidentiality → Integrity → Availability
```

In OT/ICS security, the priority order is:

```
Availability → Integrity → Confidentiality
```

**Why?**

A hospital that loses patient data (confidentiality breach) is a crisis.  
A chemical plant that loses control of a reactor (availability loss) is a catastrophe.

OT systems **must stay running**. Downtime isn't just a business cost — it can mean:
- Physical equipment damage
- Environmental harm
- Worker injury or death
- Loss of national critical infrastructure

---

## Side-by-Side Comparison

| Dimension | IT Environment | OT/ICS Environment |
|---|---|---|
| **Primary Goal** | Data processing, business ops | Physical process control |
| **Top Priority** | Confidentiality | Availability / Safety |
| **Typical Lifespan** | 3–5 years | 15–30+ years |
| **Patching** | Regular, often automated | Rare, requires downtime windows, vendor approval |
| **Antivirus** | Standard | Often impossible (legacy OS, real-time constraints) |
| **Reboots** | Routine | May require plant shutdown, shift coordination |
| **Latency Tolerance** | Seconds acceptable | Milliseconds matter (hard real-time) |
| **Protocols** | TCP/IP, HTTP, TLS | Modbus, DNP3, PROFINET, OPC, EtherNet/IP |
| **Operating Systems** | Modern, patchable | Windows XP/7, proprietary RTOS, DOS |
| **Encryption** | Standard | Rare (overhead incompatible with real-time) |
| **Network Visibility** | Good (managed infrastructure) | Often poor (undocumented legacy) |
| **Remote Access** | Routine, managed | High-risk; often via jump hosts |
| **Change Management** | Agile | Extremely rigid; requires vendor sign-off |
| **Failure Mode** | Service disruption | Physical harm, safety incidents |

---

## Key Concepts Unique to OT

### Safety Instrumented Systems (SIS)
Separate from the control system. Designed to **automatically bring a process to a safe state** when dangerous conditions are detected. SIS were the target of the **TRITON/TRISIS** malware (2017), which attempted to disable safety systems in a Saudi petrochemical plant.

### Real-Time Requirements
PLCs and RTUs operate on hard real-time cycles (scan times of 1–100ms). Any security control that introduces latency (deep packet inspection, encryption) can disrupt process control. This is why traditional IT security tools can't be dropped into OT environments without careful validation.

### Legacy Systems
It's common to find:
- PLCs from the 1990s that have never been patched
- Windows XP HMIs that cannot be replaced without re-engineering the entire line
- Protocols with **zero authentication** (Modbus has no authentication by design)

This is not negligence — it's operational reality. The systems work, vendors no longer support replacements, and stopping production to upgrade costs millions.

### The "Never Touch a Running System" Culture
OT engineers live by this principle. A change that causes a process upset can mean hours of recovery, wasted raw materials, or a dangerous condition. This means security teams must work *with* operations — not impose controls unilaterally.

---

## IT/OT Convergence

Modern facilities are connecting OT networks to IT networks (and sometimes the internet) to enable:
- Remote monitoring and predictive maintenance
- Enterprise resource planning (ERP) integration
- Data analytics on production data (IIoT)

This convergence **dramatically increases attack surface**. An attacker who compromises an IT workstation may now have a path to the control network.

**Classic convergence risks:**
- Historian servers that sit in both IT and OT zones
- VPN/remote access that bypasses air gaps
- USB drives used by vendors to transfer files (vector for Stuxnet)
- Shared Active Directory between IT and OT

---

## What OT Security Teams Actually Do

- **Asset inventory** — Map every PLC, RTU, HMI, engineer workstation (often undocumented)
- **Network segmentation** — Enforce zone separation per Purdue Model
- **Passive monitoring** — Tools like Claroty, Dragos, Nozomi watch traffic without touching devices
- **Vulnerability management** — Identify CVEs, prioritize by exploitability and operational risk
- **Incident response** — Coordinate with safety and operations during cyber events
- **Third-party/vendor risk** — Manage integrator access (a major attack vector)

---

## Common Misconceptions

| Misconception | Reality |
|---|---|
| "OT networks are air-gapped" | Most modern plants have some IT-OT connectivity; USB, cellular modems, and vendor laptops often bypass the "gap" |
| "Attackers don't know OT protocols" | Threat actors (state-sponsored especially) have deep OT expertise; tools like INDUSTROYER speak native ICS protocols |
| "Old systems can't be hacked" | Age provides no security; old systems are more vulnerable because they lack authentication and encryption |
| "We don't have anything interesting to attack" | Critical infrastructure is a high-value target for ransomware (Colonial Pipeline), espionage, and sabotage |

---

## Further Reading

- [NIST SP 800-82 Rev 3 — Guide to OT Security](https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final)
- [ICS-CERT Advisories](https://www.cisa.gov/ics-advisories)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

---

*Next: [ICS Components Glossary →](ICS-Components-Glossary.md)*
