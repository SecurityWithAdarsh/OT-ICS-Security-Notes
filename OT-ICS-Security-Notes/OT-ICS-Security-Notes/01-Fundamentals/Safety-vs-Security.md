# Safety vs Security in OT/ICS

> These two concepts are often conflated — and in OT environments, confusing them leads to dangerous gaps. Understanding how they relate (and where they conflict) is essential for ICS security professionals.

---

## Definitions

| Term | Definition |
|---|---|
| **Safety** | Protection of people, environment, and equipment from **unintentional** failures (equipment malfunction, human error, process upset) |
| **Security** | Protection of systems from **intentional** unauthorized access, manipulation, or attack |

**Key insight**: Safety engineering predates cybersecurity by decades. Safety systems were designed assuming failures are accidental. Adding a malicious adversary into the threat model is a newer, increasingly critical challenge.

---

## Where They Overlap

Both safety and security aim to prevent harm — but from different threat sources.

```
           SAFETY                 SECURITY
    (unintentional harm)     (intentional harm)

    Equipment failure    ←→    Adversarial attack
    Human error          ←→    Insider threat
    Process upset        ←→    Malicious command injection
    Component wear       ←→    Firmware manipulation
```

An attacker who targets an ICS is effectively trying to **cause the same outcomes that safety systems protect against** — but deliberately.

This is why **TRITON/TRISIS** was so alarming: it specifically targeted Safety Instrumented Systems (SIS). If successful, it would have left the plant running in a dangerous condition with no automated emergency response.

---

## Where They Conflict

This is where it gets practically important:

### 1. Availability vs Isolation
- **Safety requirement**: Emergency shutdown must respond immediately; no delays
- **Security requirement**: Network segmentation, authentication checks, firewalls
- **Conflict**: A security firewall that misclassifies an emergency command as suspicious and drops it could prevent a safe shutdown

### 2. Maintenance Access
- **Safety requirement**: Engineers must access systems quickly during abnormal conditions
- **Security requirement**: MFA, jump servers, VPN — add friction to access
- **Conflict**: During a safety incident, time matters. Security controls that slow access can worsen outcomes

### 3. Change Control
- **Safety requirement**: Every change to a safety system must be validated, tested, documented
- **Security requirement**: Patches should be applied quickly to close vulnerabilities
- **Conflict**: Patch cycle for safety systems may take 6–18 months due to validation requirements

### 4. Redundancy vs Attack Surface
- **Safety requirement**: Redundant systems, multiple communication paths to ensure control availability
- **Security requirement**: Minimize communication paths, reduce attack surface
- **Conflict**: Safety redundancy can create additional network paths that increase exposure

---

## The IEC 62443 and IEC 61511 Relationship

**IEC 61511** is the safety standard (Functional Safety for SIS in process industry).  
**IEC 62443** is the security standard (Industrial Automation and Control System Security).

In 2016, **IEC 61511 Edition 2** added a cybersecurity risk assessment requirement — recognizing that deliberate attacks on safety systems are a real threat. This formally joined the two disciplines.

Key addition: *"A cyber-security risk assessment shall be carried out to identify the cyber-security vulnerabilities of the SIS."*

---

## Defense in Depth — Bridging Both

Modern ICS protection uses multiple independent layers:

```
Layer 1: Basic Process Control System (BPCS / DCS / PLC)
           ↓ Normal control
Layer 2: Alarms and Operator Response
           ↓ Operator acts on abnormal conditions
Layer 3: Safety Instrumented System (SIS)
           ↓ Automatic safe state action
Layer 4: Physical Protection Layers
           ↓ Pressure relief valves, rupture disks, dikes
Layer 5: Emergency Services
```

A cybersecurity attack attempting to cause a process hazard must defeat **multiple layers** — not just compromise a PLC.

Security teams should understand where their controls fit in this stack and ensure they **don't inadvertently degrade a safety layer**.

---

## Practical Guidance for OT Security Practitioners

1. **Never disable a safety function to "simplify" security architecture.** Safety takes precedence.
2. **Treat the SIS as a separate security zone** — it should have its own network segment, separate from DCS.
3. **Involve safety engineers** in any security change that touches or interfaces with safety systems.
4. **Understand the HAZOP (Hazard and Operability Study)** for your facility — this document identifies the dangerous scenarios. Your threat model should align.
5. **Test your incident response process** against scenarios where the OT cyber incident and a safety incident overlap.

---

## Interview Tip

A common OT security interview question:

> *"What would you do if a security patch conflicted with a safety validation?"*

Correct answer: **Escalate to both security and safety leads. Never apply a patch to a safety system without following the change management process defined by IEC 61511 and your site's safety case documentation. The patch may need to wait for the next planned maintenance window and re-validation cycle. In the interim, compensating controls (network isolation, monitoring) should be applied.**

---

*Back: [OT vs IT Security ←](OT-vs-IT-Security.md) | Next: [Protocols →](../02-Protocols/Modbus.md)*
