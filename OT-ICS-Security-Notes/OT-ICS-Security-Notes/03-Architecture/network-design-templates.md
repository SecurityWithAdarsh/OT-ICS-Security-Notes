# OT Network Design Templates

## Template 1: Chemical Plant Reference Architecture

```
INTERNET
    │
[Edge Firewall / IPS]
    │
CORPORATE NETWORK (Level 4)
├── Active Directory Domain Controllers
├── Email / Exchange
├── ERP (SAP)
└── Corporate workstations

    │ [Perimeter Firewall — Dual-homed, restricted ruleset]
    │
IT/OT DMZ (Level 3.5)
├── Data Historian (DMZ replica — receives data push from OT)
├── Remote Access Gateway (Vendor VPN entry point)
├── Jump Server / Bastion Host (with MFA + session recording)
├── Patch Management Server (staged patch delivery to OT)
└── AV Signature Server

    │ [OT Perimeter Firewall — strict, OT protocol-aware]
    │
LEVEL 3 — Site Operations
├── Primary Historian (pushes to DMZ replica)
├── SCADA Servers (primary + redundant)
├── Engineering Workstation (EWS) — STANDALONE, not domain-joined
└── OT Patch Management (receives from DMZ, distributes to OT)

    │ [Industrial Switch with ACLs / VLAN separation]
    │
LEVEL 2 — Supervisory
├── Operator HMI Workstations (Wonderware InTouch clients)
├── Alarm Management Server
└── DCS Engineering Stations

    │ [Managed Industrial Switch — dedicated control VLAN]
    │
LEVEL 1 — Basic Control
├── Siemens S7-300/400 PLCs (Reactor Control)
├── ABB 800xA DCS Controllers
├── Safety Instrumented System (physically separate network!)
└── RTUs (remote monitoring points)

    │ [Serial / PROFINET / Modbus RTU]
    │
LEVEL 0 — Field
├── Temperature Transmitters (4-20mA → HART)
├── Pressure Sensors
├── Flow Meters
├── Control Valves (pneumatic with positioner)
└── Emergency Shutdown Valves (SIS-controlled)
```

## Template 2: IT/OT DMZ Data Flow Rules

```
PERMITTED DATA FLOWS (all others denied):

Corporate IT → DMZ:
  HTTPS (443) to Remote Access Gateway
  RDP (3389) to Jump Server (from IT admin subnet only)

OT → DMZ:
  Historian replication push: TCP 5450 (OSIsoft PI) from L3 Historian → DMZ Historian
  Syslog (UDP 514) from OT devices → DMZ Syslog Collector

DMZ → OT:
  AV signature push: from DMZ AV Server → OT endpoints (port per product)
  Patch delivery: from DMZ Patch Server → OT WSUS (TCP 8530)
  Jump Server → specific OT asset (RDP/SSH, restricted destination)

Corporate IT → OT: NEVER direct — always via DMZ
OT → Corporate IT: NEVER direct — always via DMZ
```

## Template 3: Firewall Ruleset for OT Perimeter

```
# OT Perimeter Firewall Rules (from DMZ to Level 3)
# Priority order — first match wins

Rule 1: ALLOW — Historian replication from L3 → DMZ
  Source:      192.168.30.10 (L3 Historian)
  Destination: 192.168.20.10 (DMZ Historian)
  Port:        TCP 5450 (OSIsoft PI)
  Direction:   L3 → DMZ only (unidirectional)
  Action:      PERMIT, LOG

Rule 2: ALLOW — Jump server session to EWS
  Source:      192.168.20.30 (Jump Server)
  Destination: 192.168.30.50 (EWS)
  Port:        TCP 3389 (RDP)
  Time:        Business hours + on-call window
  Action:      PERMIT, LOG, ALERT on off-hours

Rule 3: ALLOW — Patch delivery
  Source:      192.168.20.40 (Patch Server)
  Destination: 192.168.30.0/24 (L3 servers)
  Port:        TCP 8530 (WSUS)
  Action:      PERMIT, LOG

Rule 4: ALLOW — Syslog from OT
  Source:      192.168.30.0/24, 192.168.20.0/24
  Destination: 192.168.20.50 (Syslog Collector)
  Port:        UDP 514
  Direction:   OT → DMZ only
  Action:      PERMIT

Rule 5: DENY ALL — Catch-all
  Source:      ANY
  Destination: ANY
  Action:      DENY, LOG, ALERT
```
