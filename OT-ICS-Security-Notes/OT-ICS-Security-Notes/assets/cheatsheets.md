# OT/ICS Security Cheat Sheets

## Modbus TCP Quick Reference

```
PORT: 502 (TCP)

FUNCTION CODES (most critical):
FC 01  Read Coils
FC 02  Read Discrete Inputs
FC 03  Read Holding Registers      ← most common read
FC 04  Read Input Registers
FC 05  Write Single Coil           ← attack vector
FC 06  Write Single Register       ← attack vector
FC 15  Write Multiple Coils        ← attack vector
FC 16  Write Multiple Registers    ← highest risk write
FC 43  Read Device Identification  ← recon/fingerprinting

MEMORY MAP:
00001-09999  Coils (R/W digital outputs)
10001-19999  Discrete Inputs (R/O digital inputs)
30001-39999  Input Registers (R/O sensor readings)
40001-49999  Holding Registers (R/W setpoints) ← most critical

SECURITY: NO auth, NO encryption, NO integrity check
```

## Port Reference Card

```
OT PROTOCOL PORTS:
502    Modbus TCP
102    Siemens S7comm (ISO-TSAP)
4840   OPC UA (binary transport)
443    OPC UA (HTTPS transport)
20000  DNP3 (TCP/UDP)
44818  EtherNet/IP explicit messaging (TCP)
2222   EtherNet/IP implicit/I/O (UDP)
1089   Foundation Fieldbus
1090   Foundation Fieldbus
1091   Foundation Fieldbus
2404   IEC 60870-5-104
20547  ProConOS (CODESYS runtime)
1502   TriStation (Triconex SIS) UDP ← TRITON target

COMMON OT MANAGEMENT PORTS:
80/443  Web-based HMI (DANGEROUS if internet-exposed)
3389    RDP to SCADA/HMI servers
5900    VNC (often used for remote HMI access)
```

## Purdue Model Quick Reference

```
LEVEL 4: Enterprise (ERP, email, corporate IT)
         ════ IT/OT DMZ ════
LEVEL 3: Site Operations (Historian, SCADA Server, EWS)
         ════ Firewall ════
LEVEL 2: Supervisory (HMI, Operator Stations, DCS)
         ════ Switch/Firewall ════
LEVEL 1: Basic Control (PLC, RTU, DCS Controllers)
         ════ Field Bus ════
LEVEL 0: Process (Sensors, Actuators, Valves, Motors)
```

## OT CIA Priority (Inverted from IT)

```
IT:  Confidentiality → Integrity → Availability
OT:  Availability → Integrity → Confidentiality
```

## Key Standards at a Glance

```
IEC 62443  — International ICS security standard (all sectors)
             Key concepts: Zones, Conduits, Security Levels (SL 0-4)

NERC CIP   — Mandatory for US/Canada bulk electric system
             Key standards: CIP-002 to CIP-013

NIST 800-82 — US Gov guidance for OT security
              Maps to NIST CSF: Identify/Protect/Detect/Respond/Recover

NIST CSF    — Framework: Identify, Protect, Detect, Respond, Recover
MITRE ATT&CK ICS — Tactics/Techniques for ICS adversaries (14 tactics)
```

## ICS Malware Quick Reference

```
STUXNET (2010)
Target: Siemens S7 PLCs (Natanz centrifuges)
Vector: USB → WinCC/Step7
Effect: Physical destruction of centrifuges
Novel: PLC rootkit, SIS disabled, false HMI data

TRITON/TRISIS (2017)
Target: Schneider Triconex SIS
Vector: IT → OT lateral movement → EWS
Effect: Near-miss; SIS failure triggered safe shutdown
Novel: First malware explicitly targeting SIS

INDUSTROYER/CRASHOVERRIDE (2016)
Target: Ukrainian power grid (Ukrenergo)
Vector: IT compromise → SCADA
Effect: 225,000 customers lost power ~1hr
Novel: Native ICS protocol modules (IEC 61850, DNP3, OPC DA)

PIPEDREAM/INCONTROLLER (2022)
Target: Energy sector (US) — caught before deployment
Effect: None (preemptively disrupted)
Novel: Cross-vendor ICS attack framework (Schneider + Omron + CODESYS)

BLACKENERGY (2015)
Target: Ukrainian distribution companies
Vector: Spearphishing → SCADA
Effect: 225,000 customers, 1-6hrs outage
Novel: First confirmed cyber-caused power outage
```

## Wireshark OT Filter Cheatsheet

```
Modbus TCP:          tcp.port == 502
Modbus writes only:  modbus.func_code >= 5 && modbus.func_code <= 16
S7comm:              tcp.port == 102
OPC UA:              tcp.port == 4840
DNP3:                dnp3
PROFINET DCP:        pn_dcp
EtherNet/IP:         tcp.port == 44818 || udp.port == 2222
IEC 60870-5-104:     tcp.port == 2404
TriStation:          udp.port == 1502
```

## Interview Answer Templates

### "Describe IT vs OT security" (30 sec)
> "OT security inverts the CIA triad — availability comes first because shutting down a chemical reactor or power turbine has immediate physical consequences. This means we can't simply patch, can't install agents on PLCs, and can't take systems offline to investigate incidents. Instead we rely on network segmentation, compensating controls like application whitelisting, and passive monitoring that observes traffic without disrupting operations."

### "What would you do if you found an unsecured Modbus device?" (30 sec)
> "First, I'd determine if it's internet-exposed via Shodan or network config review — that's critical and immediate. Then assess reachability: who can reach port 502? If it's only accessible within the control network from authorized SCADA masters, the risk is lower. Controls I'd implement: firewall rules restricting port 502 to only the legitimate master IP, DPI rules allowlisting only read function codes from that IP, and passive monitoring to alert on any write commands from unexpected sources. Long-term: evaluate industrial firewall with Modbus protocol awareness."

### "Why can't you use Nmap in OT?" (15 sec)
> "Active scanners like Nmap send probe packets that PLCs and RTUs were never designed to receive — they can crash or lose communication, creating potential safety events. OT requires passive-only monitoring: SPAN port capture with tools like Claroty or Zeek that observe traffic without injecting anything."
