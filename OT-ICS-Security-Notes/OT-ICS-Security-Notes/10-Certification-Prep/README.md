# 10 - Certification Preparation

## GICSP (Global Industrial Cyber Security Professional)

The GICSP is offered by GIAC and is the industry-recognized certification for ICS/OT security professionals. It is jointly developed by ISA and GIAC.

### Exam Details
- **Questions:** 82–115 multiple choice/multi-answer
- **Duration:** 2 hours
- **Passing Score:** 71%
- **Open Book:** Yes (GIAC allows notes)
- **Cost:** ~$949 (exam only) or bundled with SANS ICS courses

### Domain Coverage

| Domain | Weight | Key Topics |
|---|---|---|
| **OT Landscape** | ~15% | IT vs OT differences, Purdue Model, ICS types |
| **ICS Protocols** | ~20% | Modbus, OPC, DNP3, PROFINET, fieldbus |
| **Network Security** | ~15% | Segmentation, firewalls, DMZ design |
| **Security Controls** | ~15% | Access control, hardening, patch management |
| **Risk & Governance** | ~10% | IEC 62443, NERC CIP, NIST SP 800-82, risk assessment |
| **Incident Response** | ~10% | OT IR process, forensics, notification |
| **Threats & Vulnerabilities** | ~15% | Malware families, attack vectors, CVEs |

### Recommended Study Resources
- **SANS ICS410:** ICS/SCADA Security Essentials (most aligned to GICSP)
- **SANS ICS515:** ICS Visibility, Detection, and Response
- Idaho National Laboratory ICS training (free online)
- CISA ICS-CERT training (free, available at ics-cert.us-cert.gov)
- This repository (!)

---

## Quick Reference Q&A Bank

### Fundamentals
**Q: What does CIA stand for in IT, and how is it ordered differently in OT?**
> IT: Confidentiality-Integrity-Availability. OT: Availability-Integrity-Confidentiality. OT prioritizes keeping the physical process running above all.

**Q: What is a PLC and what language does it typically use?**
> A Programmable Logic Controller is a ruggedized computer that executes control logic to operate field devices. Primary languages per IEC 61131-3: Ladder Diagram (LD), Function Block Diagram (FBD), Structured Text (ST), Instruction List (IL), Sequential Function Chart (SFC).

**Q: What is the difference between SCADA and DCS?**
> SCADA (Supervisory Control and Data Acquisition) is typically used for geographically distributed systems (pipelines, power grids) with remote RTUs communicating over WAN. DCS (Distributed Control System) is typically used for continuous process control within a single site (chemical plant, refinery) with distributed controllers on a high-speed local network.

**Q: What is a Safety Instrumented System?**
> An SIS is an independent control system that monitors process variables and automatically brings the plant to a safe state when dangerous conditions are detected. It is kept architecturally separate from the DCS to ensure it can function even if the primary control system fails or is compromised. Rated by Safety Integrity Level (SIL 1–4).

### Protocols
**Q: What port does Modbus TCP use?**  
> TCP port **502**

**Q: What port does OPC UA use?**  
> TCP port **4840** (binary transport); also **443** (HTTPS transport)

**Q: What port does Siemens S7comm use?**  
> TCP port **102** (ISO-TSAP)

**Q: What port does DNP3 use?**  
> TCP/UDP port **20000**

**Q: What port does EtherNet/IP use?**  
> TCP **44818** (explicit messaging) / UDP **2222** (implicit/I/O messaging)

**Q: What Modbus function code reads holding registers?**  
> Function Code **3** (0x03) — Read Holding Registers

**Q: What Modbus function code writes multiple registers?**  
> Function Code **16** (0x10) — Write Multiple Registers (highest attack risk)

**Q: Does Modbus TCP have authentication?**  
> No. Modbus has zero authentication, authorization, or encryption.

**Q: What is OPC DA vs OPC UA?**  
> OPC DA uses Windows DCOM, requires dynamic port ranges, NTLM auth, no encryption. OPC UA is platform-independent, uses port 4840, supports X.509 certificates and AES-256 encryption, and has role-based access control.

**Q: Why is PROFINET difficult to secure across subnets?**  
> PROFINET RT operates at Layer 2 (Ethernet frames) and is not TCP/IP routable. It cannot cross subnets without special gateway equipment.

### Architecture
**Q: List the Purdue Model levels from 0 to 4.**  
> Level 0: Field devices (sensors, actuators). Level 1: Basic control (PLCs, RTUs). Level 2: Supervisory (HMIs, DCS). Level 3: Site operations (Historians, SCADA). Level 4: Enterprise (ERP, corporate IT).

**Q: What is an IT/OT DMZ and why is it needed?**  
> A DMZ is a buffer network (Level 3.5) between corporate IT and OT control systems. It hosts systems like historians, jump servers, and remote access gateways that need to communicate with both sides. No direct connection exists between IT and OT — all traffic routes through the DMZ for inspection and control.

**Q: What is a data diode?**  
> A hardware device enforcing one-way data flow at the physical layer using fiber optics with only the TX strand connected. Makes reverse communication physically impossible regardless of software configuration.

**Q: What is the risk of a dual-homed historian?**  
> A historian with NICs on both the OT control network and the corporate IT network creates a direct bridge that bypasses the DMZ, allowing IT-side threats to pivot directly into OT.

### Threats
**Q: What malware first specifically targeted a Safety Instrumented System?**  
> TRITON (also known as TRISIS or HatMan), targeting Schneider Electric Triconex controllers at a Saudi Arabian petrochemical facility in 2017.

**Q: What was Stuxnet's primary delivery mechanism?**  
> USB drives exploiting four Windows zero-day vulnerabilities.

**Q: What ICS protocols did Industroyer/CrashOverride natively implement?**  
> IEC 61850, IEC 60870-5-101, IEC 60870-5-104, DNP3, and OPC DA.

**Q: What is the Aurora vulnerability?**  
> A condition where rapidly cycling a circuit breaker out-of-phase with a generator causes mechanical stress leading to physical destruction of the generator — achievable through network commands to grid control systems.

**Q: What initial access vector was used in the Colonial Pipeline attack?**  
> A compromised VPN account with no multi-factor authentication.

**Q: Was the Colonial Pipeline's OT system directly compromised?**  
> No. Colonial's IT billing systems were ransomed; Colonial voluntarily shut down OT operations out of caution for potential spread.

### Controls
**Q: Why can't you run Nmap against OT devices?**  
> Active scanning tools send probe packets that OT devices (PLCs, RTUs) were never designed to receive. These can cause PLC crashes, memory corruption, or loss of communication, creating safety events. Passive-only monitoring is required.

**Q: What is application whitelisting in an OT context?**  
> A control that allows only pre-approved executables to run on a system. In OT, HMIs run a fixed set of software (SCADA client, engineering tools) that rarely changes, making whitelisting highly effective. Tools like Trellix Application Control are common for legacy Windows OT systems.

**Q: What is virtual patching?**  
> When a vulnerability cannot be patched directly (due to OT constraints), a network-layer control blocks traffic that could exploit it. For example, a deep packet inspection firewall rule blocking the specific request pattern used to exploit a vulnerable OPC DA endpoint.

**Q: What is the most critical OT asset to secure and why?**  
> The Engineering Workstation (EWS). It has direct PLC programming access via TIA Portal or RSLogix. Compromising the EWS = ability to reprogram any PLC on the network. It should be standalone (not on corporate domain), application-whitelisted, USB-disabled, and physically locked.

### Standards
**Q: What is IEC 62443?**  
> The international standard series for Industrial Automation and Control Systems (IACS) security. It defines Security Levels (SL 0–4), the Zone/Conduit model for segmentation, and requirements for system components, system design, and operations.

**Q: What does NERC CIP stand for and who does it apply to?**  
> North American Electric Reliability Corporation Critical Infrastructure Protection. It applies to operators of the bulk electric system (BES) in the US and Canada. It is mandatory with financial penalties for non-compliance.

**Q: What is NIST SP 800-82?**  
> NIST Special Publication 800-82 "Guide to Operational Technology (OT) Security" — the primary US government guidance for OT/ICS security, providing threat overviews, network architecture guidance, and security control recommendations for ICS environments.

**Q: What are the NIST CSF functions?**  
> Identify, Protect, Detect, Respond, Recover.

---

## Additional Certifications

| Certification | Provider | Focus |
|---|---|---|
| **GICSP** | GIAC/ISA | General ICS security (most recognized) |
| **GRID** | GIAC | ICS incident response |
| **CSSA** | ISACA | SCADA security |
| **CompTIA CySA+** | CompTIA | Includes OT/ICS modules in latest version |
| **ISA/IEC 62443 Cybersecurity Certificate** | ISA | IEC 62443 standard specifically |
| **Claroty Certified Specialist** | Claroty | Claroty platform + OT security concepts |
| **Dragos ICS Operations** | Dragos | ICS threat hunting and response |

---

## Study Tips for GICSP

1. **Know the protocols cold:** Modbus function codes, OPC DA vs UA, DNP3 SA — always tested
2. **Understand CIA inversion:** Every scenario question involves availability-first thinking
3. **Purdue Model levels:** Know exactly what lives at each level
4. **IEC 62443 vocabulary:** Zones, conduits, security levels — expect multiple questions
5. **Case studies:** TRITON, Stuxnet, Ukraine grid — understand attack chains and lessons
6. **Compensating controls:** Memorize why standard IT controls don't apply and what replaces them
7. **Make notes for the exam:** GICSP is open-book — organize this repository as your reference!
