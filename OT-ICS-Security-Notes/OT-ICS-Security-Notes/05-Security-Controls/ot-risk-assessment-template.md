# OT Risk Assessment Template

## Asset Risk Scoring Matrix

For each OT asset, score the following:

### Step 1: Consequence Rating (C)
| Score | Level | Criteria |
|---|---|---|
| 5 | Critical | Safety event possible (SIS, ESD, safety valves) |
| 4 | High | Major production loss >24hrs OR environmental release possible |
| 3 | Medium | Production disruption 4-24hrs |
| 2 | Low | Production disruption <4hrs, recoverable |
| 1 | Minimal | Non-production, auxiliary systems |

### Step 2: Vulnerability Rating (V)
| Score | Level | Criteria |
|---|---|---|
| 5 | Critical | Internet-exposed, no auth, known unpatched CVE actively exploited |
| 4 | High | Network-accessible from IT, no auth, known CVE |
| 3 | Medium | OT-network accessible, no auth, legacy OS/firmware |
| 2 | Low | Isolated subnet, some compensating controls |
| 1 | Minimal | Physically isolated or hardened with multiple controls |

### Step 3: Likelihood (L) — based on threat actors targeting sector
| Score | Criteria |
|---|---|
| 5 | Nation-state actively targeting this sector/technology |
| 4 | Known ransomware groups targeting sector |
| 3 | General opportunistic attackers can reach |
| 2 | Requires insider or physical access |
| 1 | Requires highly specialized knowledge |

### Risk Score = C × V × L

| Score Range | Risk Level | Action |
|---|---|---|
| 75–125 | Critical | Immediate remediation; escalate to CISO |
| 40–74 | High | Remediate within 30 days |
| 15–39 | Medium | Remediate within 90 days or accept with controls |
| 1–14 | Low | Accept risk; review annually |

---

## Sample Risk Assessment (Chemical Plant)

| Asset | Description | C | V | L | Score | Risk | Controls |
|---|---|---|---|---|---|---|---|
| S7-300 PLC (Reactor A) | Controls temp/pressure for reactor | 5 | 3 | 3 | 45 | **HIGH** | VLAN isolation, passive monitoring, disable unused ports |
| Wonderware HMI | Operator interface Level 2 | 4 | 3 | 3 | 36 | Medium | App whitelist, no USB, local accounts only |
| Engineering WS | TIA Portal PLC programming | 5 | 2 | 3 | 30 | Medium | Standalone (no AD), USB disabled, physical lock |
| Triconex SIS | Safety system ESD control | 5 | 1 | 2 | 10 | Low | Physical isolation, separate network, air-gap |
| L3 Historian | Wonderware System Platform | 3 | 4 | 3 | 36 | Medium | DMZ data push only, no direct OT access |
| OPC DA Server | Bridges HMI↔PLC (Windows 2012) | 4 | 4 | 3 | 48 | **HIGH** | DCOM restricted, host firewall, isolate, plan upgrade |

---

## Risk Register Template

```
Risk ID:        RISK-OT-001
Asset:          Siemens S7-300 PLC — Reactor A
Vulnerability:  No authentication on S7comm (port 102)
Threat:         Unauthorized programming by attacker reaching Level 1 network
Consequence:    Process manipulation leading to safety event
Likelihood:     Medium (requires Level 1 network access; currently segmented)
Risk Score:     45 (HIGH)

Current Controls:
  - Level 1 network isolated on dedicated VLAN
  - Only EWS IP permitted to reach port 102 (firewall ACL)
  - Physical key switch in RUN mode prevents program changes
  - Passive monitoring alerts on unexpected S7comm connections

Residual Risk:  MEDIUM (controls reduce likelihood)
Action:         Enable PLC password protection in next maintenance window (Q2)
Owner:          [Automation Engineer Name]
Review Date:    Q2 2024
```
