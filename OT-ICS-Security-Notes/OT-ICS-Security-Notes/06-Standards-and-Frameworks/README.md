# 06 - OT/ICS Standards and Frameworks

## IEC 62443

The **IEC 62443** series (also known as ISA/IEC 62443) is the primary international standard for Industrial Automation and Control Systems (IACS) security. It covers the entire lifecycle of ICS security from requirements through operations.

### Standard Structure

| Standard | Scope |
|---|---|
| IEC 62443-1-1 | Terminology, concepts, models |
| IEC 62443-2-1 | IACS Security Management System requirements |
| IEC 62443-2-4 | Security requirements for IACS service providers |
| IEC 62443-3-2 | Security risk assessment for system design |
| IEC 62443-3-3 | System security requirements and security levels |
| IEC 62443-4-1 | Product development security requirements |
| IEC 62443-4-2 | Technical security requirements for components |

### Key Concepts

**Security Levels (SL 0–4)**
| Level | Definition | Example |
|---|---|---|
| SL 0 | No specific requirements | Non-critical auxiliary equipment |
| SL 1 | Protection against casual/unintentional violation | Basic process area |
| SL 2 | Protection against intentional violation using simple means | Control room |
| SL 3 | Protection against sophisticated attack with ICS resources | Critical process control |
| SL 4 | Protection against state-sponsored sophisticated attack | Safety-critical only |

**Zones and Conduits Model**
- **Zone:** A grouping of OT assets with similar security requirements
- **Conduit:** A communication path between two zones — must be explicitly secured
- Every conduit requires a defined Security Level and controls

### Foundational Requirements (FR)
IEC 62443-3-3 defines 7 Foundational Requirements:

| FR | Requirement |
|---|---|
| FR 1 | Identification and Authentication Control |
| FR 2 | Use Control (authorization, least privilege) |
| FR 3 | System Integrity |
| FR 4 | Data Confidentiality |
| FR 5 | Restricted Data Flow (segmentation) |
| FR 6 | Timely Response to Events (incident response, logging) |
| FR 7 | Resource Availability |

---

## NIST SP 800-82

**NIST Special Publication 800-82 Rev 3:** "Guide to Operational Technology (OT) Security"

The primary US government guidance for OT security, published by NIST. Rev 3 (2023) is the current version.

### Key Sections
- **Chapter 3:** OT overview, threats, vulnerabilities
- **Chapter 4:** OT security program (risk management, governance)
- **Chapter 5:** Network architecture (Purdue Model, DMZ, segmentation)
- **Chapter 6:** OT-specific security controls mapped to NIST SP 800-53

### NIST CSF Mapping to OT

The NIST Cybersecurity Framework (CSF) functions apply to OT:

| Function | OT Interpretation |
|---|---|
| **Identify** | Asset inventory, OT risk assessment, network topology documentation |
| **Protect** | Segmentation, access control, patch management, hardening |
| **Detect** | Passive monitoring, SIEM integration, behavioral baselines |
| **Respond** | OT-specific IR playbooks, vendor coordination, containment |
| **Recover** | Backup/restore of PLC programs, process restart procedures |

---

## NERC CIP

**North American Electric Reliability Corporation Critical Infrastructure Protection** — mandatory standards for the bulk electric system in North America.

### Key Standards
| Standard | Topic |
|---|---|
| CIP-002 | BES Cyber System Categorization (identify critical assets) |
| CIP-003 | Security Management Controls |
| CIP-004 | Personnel and Training |
| CIP-005 | Electronic Security Perimeters (network segmentation, ESP) |
| CIP-006 | Physical Security of Cyber Assets |
| CIP-007 | Systems Security Management (ports, services, patching) |
| CIP-008 | Incident Reporting and Response Planning |
| CIP-009 | Recovery Plans |
| CIP-010 | Configuration Change Management and Vulnerability Management |
| CIP-011 | Information Protection |
| CIP-013 | Supply Chain Risk Management |

### CIP-005 Electronic Security Perimeter
The ESP is the network boundary around BES Cyber Systems:
- All communication into the ESP must go through an Electronic Access Point (EAP)
- EAPs must be firewalled; traffic must be authorized
- Remote access via Interactive Remote Access must use encryption and MFA
- This is essentially the NERC-mandated version of the Purdue DMZ

---

## NIST SP 800-53 Controls for OT

Selected controls from NIST SP 800-53 most relevant to OT:

| Control Family | Key Controls | OT Application |
|---|---|---|
| **AC (Access Control)** | AC-2 (Account Mgmt), AC-17 (Remote Access) | EWS accounts, vendor VPN |
| **AU (Audit)** | AU-2 (Events to Audit), AU-9 (Protection of Audit Info) | Log all EWS sessions, protect SCADA logs |
| **CM (Config Mgmt)** | CM-2 (Baseline), CM-7 (Least Functionality) | PLC baseline, disable unused OPC endpoints |
| **IA (Identification/Auth)** | IA-2 (Identification), IA-5 (Authenticator Mgmt) | MFA for remote access, password rotation |
| **IR (Incident Response)** | IR-4 (Handling), IR-8 (Plan) | OT-specific playbooks |
| **MA (Maintenance)** | MA-4 (Nonlocal Maintenance) | Session recording for remote vendor maintenance |
| **SC (System/Comm Protection)** | SC-7 (Boundary Protection), SC-28 (Protection at Rest) | DMZ, historian encryption |
| **SI (System Integrity)** | SI-3 (Malware Protection), SI-7 (Software Integrity) | Application whitelisting, firmware hash |

---

## MITRE ATT&CK for ICS

Covered in detail in [04-Threats-and-Attacks](../04-Threats-and-Attacks/). Summary:

- Framework of adversary **Tactics, Techniques, and Procedures (TTPs)** specific to ICS
- 14 tactic categories from Initial Access through Impact
- Maps techniques to real-world malware (Stuxnet, TRITON, Industroyer)
- Use for: threat modeling, detection rule development, purple team exercises, gap analysis

---

## CISA Resources

The US Cybersecurity and Infrastructure Security Agency provides:
- **ICS-CERT Advisories:** Vulnerability notifications for ICS products
- **ICS-CERT Assessments:** On-site security assessments for critical infrastructure
- **GrassMarlin:** Open-source passive ICS network mapping tool
- **CSET (Cyber Security Evaluation Tool):** Self-assessment tool mapped to NERC CIP, NIST
- **NCAS:** National Cybersecurity Awareness resources

Subscribe: https://www.cisa.gov/uscert/ics

---

## Interview Q&A

**Q: What is IEC 62443 and how is it structured?**
> IEC 62443 (also called ISA/IEC 62443) is the international standard series for industrial control system security. It's structured across four series covering general concepts, policies/procedures, system-level requirements, and component-level requirements. Key concepts include Security Levels (SL 0–4) defining protection targets from no requirements to state-sponsored attack protection, and the Zone/Conduit model for network segmentation where every communication path between security zones must be explicitly justified and secured.

**Q: What is the difference between IEC 62443 and NERC CIP?**
> NERC CIP is mandatory for US/Canadian bulk electric system operators and focuses specifically on the electric sector with prescriptive compliance requirements and financial penalties. IEC 62443 is a voluntary international standard applicable across all industrial sectors (chemical, manufacturing, oil/gas, etc.) that provides a more comprehensive security framework covering product development, system design, and operations. NERC CIP is compliance-driven; IEC 62443 is risk-driven.

**Q: How does the NIST CSF apply to OT security?**
> The five NIST CSF functions (Identify, Protect, Detect, Respond, Recover) map directly to OT but with OT-specific implementations. "Identify" means passive asset discovery rather than active scanning. "Protect" means network segmentation and application whitelisting as compensating controls for unpatchable systems. "Detect" means passive OT IDS rather than agent-based EDR. "Respond" means OT-specific playbooks that account for operational continuity. "Recover" means restoring PLC programs and historian data, not just server backups.
