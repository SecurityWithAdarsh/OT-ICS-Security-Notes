# 08 - OT/ICS Incident Response

## Key Differences from IT Incident Response

| Aspect | IT IR | OT IR |
|---|---|---|
| **First priority** | Contain/eradicate threat | **Maintain safe operation of physical process** |
| **Isolation** | Isolate infected system immediately | Cannot isolate a PLC running a live reactor |
| **Shutdown** | Take system offline to investigate | Production shutdown = financial + safety risk |
| **Forensics** | Full disk image anytime | Cannot power off PLC for imaging |
| **Recovery** | Restore from backup | Restore PLC program + verify process returns to safe state |
| **Communication** | IT team + management | IT team + OT engineers + operations + safety team |
| **Vendor involvement** | Optional | Often mandatory (Siemens, Schneider engineers) |
| **Timelines** | Hours to days | May take weeks (production restart procedures) |

---

## OT Incident Response Process

### Phase 1: Preparation
- Maintain current asset inventory with communication baselines
- Establish OT-specific IR playbooks (separate from IT playbooks)
- Identify OT IR team roles: OT security, process engineer, operations lead, safety officer
- Pre-establish vendor emergency contacts (Siemens, Schneider, Rockwell PSIRTs)
- Backup PLC programs, SCADA configurations, historian databases — stored offline
- Maintain spare hardware (PLCs, switches) for critical systems
- Establish communication tree: who to call, in what order, at what severity

### Phase 2: Detection and Analysis
- OT monitoring alert OR operator reports anomaly
- **Immediate questions:**
  - Is the physical process currently in a safe state?
  - Is there any indication of active manipulation of PLCs or setpoints?
  - Is SCADA/HMI still showing accurate data (or potentially compromised)?
- Collect: network capture from SPAN port, SCADA historian data, Windows event logs from EWS/HMI
- Do NOT use standard IT forensic tools on live OT systems without vendor confirmation

### Phase 3: Containment (OT-Specific Approach)

**Option A: Network Isolation (preferred if process can continue)**
```
1. Block all inbound connections to affected OT zone at perimeter firewall
2. Disable remote access to OT network immediately
3. Process continues running on local PLC logic (no SCADA needed for short term)
4. Move HMI/SCADA to manual/local operator control if needed
5. Isolate specific compromised hosts (EWS, Historian) from OT network
```

**Option B: Safe Process Shutdown (if process is actively manipulated)**
```
1. Notify operations team and safety officer FIRST
2. Follow normal shutdown procedure (not emergency unless safety at risk)
3. Verify SIS/ESD is operational before shutdown
4. Put process into safe state per P&ID procedures
5. Only then begin full network isolation and forensics
```

**Option C: Continued Monitoring (if threat is passive/espionage)**
```
1. Do not tip off attacker
2. Increase monitoring granularity
3. Preserve forensic evidence while process continues
4. Plan remediation for next planned maintenance window
```

### Phase 4: Eradication
- Rebuild compromised systems from verified clean backups or fresh OS
- Reload PLC programs from offline backups (verify hash)
- Change all OT passwords (PLC, HMI, SCADA, VPN, jump server)
- Revoke and reissue vendor remote access credentials
- Verify no malicious code remains in PLC firmware (compare against baseline)
- Patch vulnerabilities that enabled the compromise

### Phase 5: Recovery
- Stage return to operations in controlled sequence
- Verify process returns to correct operating parameters (not attacker-modified setpoints)
- Monitor closely for 24–72 hours after return to service
- Gradually restore remote access with enhanced controls

### Phase 6: Post-Incident
- Document timeline, affected systems, attacker TTPs
- Report to CISA ICS-CERT (mandatory for critical infrastructure in some sectors)
- Root cause analysis
- Update IR playbooks, detection rules, network controls

---

## OT Forensics Considerations

### What You Can Collect in OT (Without Disrupting Operations)
- **Network captures:** Passive SPAN/TAP (no disruption)
- **SCADA historian data:** Export process trends showing anomalies
- **Windows event logs:** From HMI/EWS (if Windows-based)
- **Firewall logs:** Border firewall logs showing connections
- **OT IDS alerts:** If passive monitoring was deployed

### What You Cannot Do in OT
- Memory dump of a running PLC (may cause reboot)
- Power off a PLC for disk imaging (no "disk" in traditional sense)
- Install forensic agents on live PLCs
- Take a running HMI offline for forensics without arranging manual operation

### PLC-Specific Forensics
```
Evidence from PLCs:
├── Current PLC program (upload from PLC, compare to backup)
├── PLC diagnostic buffer (Siemens S7: CPU → Diagnostics Buffer)
├── PLC system log (if supported)
├── Last modified timestamps on function blocks
├── Communication statistics (connection counts, error counts)
└── Current register/memory values (snapshot)

Tools:
├── TIA Portal → Upload PLC program for comparison
├── Step 7 (legacy) → Compare offline backup vs current
├── Vendor-specific: Siemens S7comm read via snap7 (in lab)
└── Network capture → baseline vs incident period comparison
```

---

## OT Incident Severity Classification

| Severity | Criteria | Response Time |
|---|---|---|
| **Critical** | Active process manipulation; physical safety at risk; SIS disabled | Immediate — halt process if needed |
| **High** | Confirmed attacker presence in OT network; HMI/SCADA compromised | 1 hour |
| **Medium** | Attacker in IT/Level 3 with no confirmed OT access; suspicious OT traffic | 4 hours |
| **Low** | IT-side indicators with potential OT relevance; policy violation | 24 hours |

---

## Reporting and Notifications

### Internal Notification Chain
```
OT Security Analyst
    ↓
OT Security Manager / CISO
    ↓
Plant Operations Manager (for potential shutdown decision)
    ↓
Safety Officer (if safety risk)
    ↓
Executive leadership (if significant impact)
    ↓
Legal / Communications (for external disclosure)
```

### External Notifications
- **CISA ICS-CERT:** https://www.cisa.gov/report — Report significant ICS incidents
- **Sector-specific ISAC:** E-ISAC (electric), WaterISAC, ONG-ISAC (oil & gas)
- **Vendor PSIRT:** Siemens ProductCERT, Schneider PSIRT, Rockwell Automation PSIRT
- **Law enforcement:** FBI (cybercrime) for significant attacks

---

## Interview Q&A

**Q: How does OT incident response differ from IT incident response?**
> The fundamental difference is that in OT, the physical process takes priority over security response. You cannot simply isolate a PLC running a chemical reactor or power turbine. The first question in an OT incident is always "Is the physical process in a safe state?" Before any containment action, you must coordinate with operations and safety teams. Containment options shift from "shut it down" to "isolate only what won't impact the process" and "move to manual/local control." Recovery isn't just restoring servers — it means verifying PLC programs are clean, setpoints are correct, and the physical process returns to expected parameters.

**Q: What would you do if you detected an unauthorized Modbus write command to a PLC?**
> Immediately notify the operations team and alert the on-call process engineer — the first priority is verifying the physical process is safe. Simultaneously capture network traffic from the SPAN port to preserve evidence. Check if the write came from an unauthorized source IP and what register was written — cross-reference the P&ID to understand the physical significance of that register. Block the source IP at the Level 1/2 firewall to prevent further writes. If the setpoint was changed to an unsafe value, the operations team would correct it via the legitimate HMI. Then begin full incident investigation: how did that source get onto the control network?
