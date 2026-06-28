# OT/ICS Security — Master Interview Prep Guide

> Compiled for roles at: Claroty, Dragos, Siemens Energy, Honeywell, Schneider Electric, ABB, Rockwell Automation, plus any SOC/Blue team position with OT scope.

---

## Round 1: Screening (HR / Recruiter)

**"Tell me about your OT security experience."**
> "I interned in the Information Security team at Aarti Industries, a large chemical manufacturing company, where I worked directly inside a live plant environment. I observed and documented the security posture of Siemens S7-300 PLCs controlled via Wonderware SCADA, analyzed Modbus TCP and OPC DA traffic, and assessed the network architecture against the Purdue Model. This gave me hands-on exposure to the OT security challenges that most people only read about — things like the reality of 10-year-old PLC firmware, shared engineering workstation credentials, and the operational constraints that prevent standard IT security practices."

**"Why OT security specifically?"**
> "IT security is where I started, but OT is where security has the most tangible physical consequence. A misconfiguration in an enterprise system costs data. A misconfiguration in a PLC at a chemical plant or power grid can cost lives or infrastructure. That stakes gap drives me — I want to work in the space where security decisions have real-world physical impact."

---

## Round 2: Technical Screen

**"Walk me through the Purdue Reference Model."**
> "The Purdue Model organizes ICS networks into five levels. Level 0 is the physical process — sensors, actuators, valves. Level 1 is basic control — PLCs and RTUs executing control logic. Level 2 is supervisory — HMIs and operator workstations. Level 3 is site operations — historians, SCADA servers, engineering workstations. Level 4 is enterprise IT — ERP, email, corporate systems. Between Level 3 and 4 sits the IT/OT DMZ. The security principle is that each level communicates only with adjacent levels, and all cross-boundary traffic passes through firewalls or DMZs. This segmentation limits lateral movement — an attacker who compromises IT cannot directly reach PLCs."

**"Modbus has no authentication. How do you secure it?"**
> "Since you can't add authentication to Modbus itself, you layer compensating controls around it. At the network level: firewall rules allowing only the legitimate SCADA master IP to reach port 502 on PLC subnets. At the protocol level: an industrial DPI firewall that allowlists specific function codes — read-only codes from SCADA, writes only from the EWS during change windows. At the monitoring level: passive IDS alerting on any write function codes (FC 5, 6, 15, 16) from unexpected source IPs, or at unusual times. Unidirectional gateways if the use case only requires reading data. The core principle is: make the network path to Modbus extremely restricted so the absence of protocol-level security is compensated by network controls."

**"What's the difference between passive and active monitoring in OT, and which do you use?"**
> "Active monitoring involves sending probe packets — Nmap, Nessus — to discover assets and test for vulnerabilities. In OT this is dangerous because PLCs and RTUs were never designed to handle unexpected packets, and can crash, lose communication, or enter fault states when they receive them. A crashed PLC controlling a live process is a safety event. Passive monitoring uses a SPAN or TAP port to capture a copy of all traffic on the wire without injecting anything — zero operational risk. You can build a complete asset inventory, communication map, and behavioral baseline purely from observed traffic. In OT environments, passive-only is the rule at Levels 0–2."

---

## Round 3: Deep Technical

**"How does OPC Classic differ from OPC UA from a security perspective?"**
> "OPC Classic uses Windows DCOM, which was designed for reliability not security. DCOM requires opening dynamic port ranges (49152–65535) on firewalls, uses NTLM authentication vulnerable to pass-the-hash, and has no data encryption. In practice, DCOM security hardening is often disabled for compatibility. OPC UA was designed from scratch with security as a requirement. It uses a defined TCP port (4840), X.509 certificate authentication, AES-256 encryption, message integrity signing, and role-based access control. The critical caveat: many OT deployments run OPC UA with SecurityMode=None for compatibility reasons — which completely negates its security model. That's a configuration finding I'd flag immediately in any assessment."

**"Describe a TRITON/TRISIS attack — why is it significant?"**
> "TRITON targeted the Schneider Electric Triconex Safety Instrumented System at a Saudi petrochemical plant in 2017. It's uniquely significant because it explicitly targeted the safety layer — the last independent system designed to prevent catastrophic physical events. Previous OT attacks targeted control systems to disrupt operations. TRITON's goal was to disable the SIS before causing a process upset, so that when the process went out of safe bounds, there would be no automatic protection. It was discovered accidentally: a bug caused the SIS to fail safe and trigger an unplanned shutdown. If it had worked, the result could have been an uncontrolled chemical release or explosion. This fundamentally changed how the industry thinks about SIS security — from 'separate network is enough' to 'must treat SIS as a primary attack target.'"

**"You're monitoring an OT network and see a Modbus FC 0x10 write command from an IP you don't recognize. Walk me through your response."**
> "First, cross-reference the source IP against the asset inventory — is this a registered device or completely unknown? Second, check what register was written and what that register controls — cross-reference the P&ID or SCADA tag database. A write to a temperature setpoint register is very different from a write to a pump enable register. Third, notify the operations team immediately — they need to verify the physical process is behaving correctly. Fourth, check the firewall and switch logs — how did this IP get network access to the PLC subnet? Was there a recent network change? Fifth, capture ongoing traffic for forensics. Containment: block the source IP at the Level 1/2 firewall. If the register was written to an unsafe value, the operations team corrects it via the legitimate HMI. Then start the IR process: how did an unauthorized device reach the control network?"

---

## Claroty-Specific Questions

**"What does Claroty CTD detect that a standard SIEM cannot?"**
> "Standard SIEMs ingest log data. Most OT devices — PLCs, RTUs, older HMIs — produce no logs whatsoever. Claroty CTD passively monitors network traffic and understands 300+ industrial protocols at the application layer. It builds a behavioral baseline: which devices exist, what they talk to, which function codes appear in normal operations. It then detects deviations: a new device appearing, an engineering tool connecting to a PLC at 3am, a Modbus write from a new source IP, a device suddenly communicating with something it has never communicated with before. All of this is invisible to a log-based SIEM because it's not generating logs — it's observable only on the wire."

---

## Dragos-Specific Questions

**"What OT threat groups has Dragos tracked?"**
> "Dragos tracks ICS-specific threat groups with code names. Chernovite is the group behind Pipedream/INCONTROLLER (2022), a cross-vendor ICS attack framework. Electrum is associated with Industroyer and the Ukraine power grid attacks. Kamacite provides initial access services for ICS-focused threat actors. Xenotime is associated with TRITON. Each group Dragos tracks has documented ICS-specific TTPs, target sectors, and known tooling — which feeds the platform's detection logic with ICS-specific threat intelligence rather than generic IT threat intel."

---

## Scenario-Based Questions

**"A vendor needs remote access to troubleshoot a Siemens PLC. How do you set this up securely?"**
> "I'd never give the vendor direct internet-facing access to the OT network. The secure architecture: vendor connects via VPN to a remote access gateway in the IT/OT DMZ. The gateway enforces MFA — hardware token or authenticator app. From there, they access a jump server (bastion host) in the DMZ, also with MFA. Session recording is enabled — full keystroke and screen capture for the entire session. Network ACLs on the jump server restrict the vendor's reachable destinations to only their specific PLC IP and only the required port (102 for Siemens S7comm). The vendor's machine must pass a health check (AV current, patched OS) before session is established. The session is time-windowed — I create the access for the scheduled maintenance window and disable it after. An OT security team member monitors the session in real-time. After the session, I review the recording, check historian data for any setpoint changes, and verify PLC program integrity."

**"How would you respond if a plant operator reported that their HMI is showing incorrect sensor readings?"**
> "This could be a sensor failure, a SCADA configuration issue, or a security incident (false data injection). My first questions: Is the physical process actually behaving abnormally, or are readings just wrong on screen? Are operators using local indicators or field instruments that tell a different story? I'd get the operations team to verify field instrument readings independently of SCADA. Simultaneously, I'd pull the passive monitoring data — has there been any Modbus or OPC activity targeting the registers that feed those display tags? Any new source IPs? Any write operations in the historian that shouldn't have occurred? If network data shows external writes to those registers, this escalates to a security incident. If the network data is clean, it's likely a sensor or SCADA engineering issue. Either way, the physical process status is confirmed first before any security response."

---

## Questions TO ASK the Interviewer

For Claroty/Dragos:
- "How does your platform handle passive discovery of devices that are air-gapped and never generate network traffic?"
- "What's your approach to helping customers when their OT environment has no SPAN port capability on aging unmanaged switches?"
- "How do you handle the cultural challenge of OT engineers who see security as a threat to availability?"

For Siemens/Honeywell/Schneider:
- "How does the security team interact with product teams when a vulnerability is found in OT firmware?"
- "What's the process for issuing and qualifying security patches for products with 20-year field lifespans?"
- "How do you balance IEC 62443 certification requirements with the engineering realities of legacy installed base?"
