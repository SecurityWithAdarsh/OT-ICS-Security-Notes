# 02 - OT/ICS Protocols

## Table of Contents
1. [Modbus TCP/RTU](#modbus-tcprtu)
2. [OPC Classic & OPC UA](#opc-classic--opc-ua)
3. [DNP3](#dnp3)
4. [PROFINET](#profinet)
5. [EtherNet/IP](#ethernetip)
6. [Protocol Security Comparison](#protocol-security-comparison)
7. [Wireshark Filters Cheatsheet](#wireshark-filters-cheatsheet)
8. [Interview Q&A](#interview-qa)

---

## Modbus TCP/RTU

### Overview
Modbus is the **oldest and most widely deployed** industrial protocol, originally developed in 1979 by Modicon. It is simple, open, and present in virtually every industrial environment.

- **Modbus RTU:** Serial communication over RS-232/RS-485. Binary encoding. Used for field device communication.
- **Modbus TCP:** Modbus framing encapsulated in TCP/IP. Default port **502**. No native encryption or authentication.

### Protocol Architecture
```
Master (HMI/SCADA)  ──request──►  Slave (PLC/RTU/Sensor)
                    ◄──response──
```
- **One master, up to 247 slaves** (RTU mode)
- Strictly **request-response** — slaves cannot push data unsolicited

### Modbus Function Codes

| Code (Dec) | Code (Hex) | Function | Security Relevance |
|---|---|---|---|
| 1 | 0x01 | Read Coils | Reconnaissance |
| 2 | 0x02 | Read Discrete Inputs | Reconnaissance |
| 3 | 0x03 | Read Holding Registers | **Most common** — reads sensor/setpoint data |
| 4 | 0x04 | Read Input Registers | Reconnaissance |
| 5 | 0x05 | Write Single Coil | **Attack vector** — toggle a valve/motor |
| 6 | 0x06 | Write Single Register | **Attack vector** — change single setpoint |
| 15 | 0x0F | Write Multiple Coils | **Attack vector** — mass digital output change |
| 16 | 0x10 | Write Multiple Registers | **Critical** — change multiple setpoints at once |
| 43 | 0x2B | Read Device Identification | Device fingerprinting / enumeration |

### Modbus Memory Map
| Address Range | Type | R/W | Description |
|---|---|---|---|
| 00001–09999 | Coils | R/W | Digital outputs (valve open/close, motor start/stop) |
| 10001–19999 | Discrete Inputs | R only | Digital inputs (limit switches, alarm contacts) |
| 30001–39999 | Input Registers | R only | Analog inputs (sensor readings: temp, pressure, flow) |
| 40001–49999 | Holding Registers | R/W | Analog outputs/setpoints (most critical for attacks) |

### Security Weaknesses
```
❌ No authentication    — Any IP on network can send commands
❌ No authorization     — No read-only vs read-write concept
❌ No encryption        — All traffic in plaintext (Wireshark readable)
❌ No message integrity — Commands cannot be verified as legitimate
❌ No audit logging     — PLCs don't log incoming Modbus commands
❌ Broadcast enumeration — FC 0x2B reveals device info unauthenticated
```

### Real Attack Scenarios
```
1. RECONNAISSANCE
   nmap -p 502 192.168.1.0/24              # Find all Modbus devices
   FC 0x2B → identify vendor, firmware     # Device fingerprinting

2. PROCESS MANIPULATION
   FC 0x10 to holding register 40001       # Change reactor temp setpoint
   → 80°C normal → attacker writes 220°C  # Runaway reaction

3. FALSE DATA INJECTION
   FC 0x06 → modify input register values  # Fake "normal" sensor readings
   → SCADA shows 80°C, actual is 180°C    # Operator deceived

4. DENIAL OF SERVICE
   Flood master with requests              # Starve legitimate polling
   → PLC does not receive new setpoints    # Process runs on stale data
```

> **Field Note (Aarti Industries):** Modbus TCP on port 502 was used to poll temperature/pressure sensors across the plant floor. The port was accessible across the Level 1 control network with no host-based restrictions. A passive Wireshark capture immediately revealed all device addresses, register maps, and live sensor readings.

### Defensive Controls
- Firewall rules: allow only legitimate master IPs to reach port 502
- Industrial DPI firewall: allowlist specific Function Codes per source/destination
- Passive monitoring: alert on FC 0x10/0x05/0x06 from unexpected sources
- Network segmentation: Modbus traffic stays within Level 0/1 only
- Unidirectional gateway: if SCADA only needs to read, enforce read-only

---

## OPC Classic & OPC UA

### OPC Classic (OLE for Process Control)
Windows-based middleware standard using **DCOM** to enable vendor-neutral HMI↔PLC communication. Three key specifications:

| Spec | Purpose | Notes |
|---|---|---|
| **OPC DA** | Real-time Data Access | Most common; read/write live process data |
| **OPC HDA** | Historical Data Access | Trend data from historians |
| **OPC A&E** | Alarms & Events | Subscribe to alarm notifications |

**Typical Deployment:**
```
OPC Client (Wonderware InTouch HMI)
        ↕ DCOM (dynamic ports 49152–65535)
OPC Server (Siemens S7 OPC Server)
        ↕ PROFINET / Industrial Ethernet
Siemens S7-300/400 PLC
```

**OPC Classic Security Problems:**
```
❌ DCOM-based         — Windows-only, firewall-hostile, dynamic port ranges
❌ NTLM auth          — Vulnerable to pass-the-hash attacks
❌ DCOM often disabled — "Compatibility" configurations remove protections  
❌ Elevated privileges — OPC servers often run as SYSTEM or local admin
❌ No data encryption  — Process data in plaintext via DCOM
```

### OPC UA (Unified Architecture)
Platform-independent successor to OPC Classic. Built from scratch with security in mind.

**Default Ports:** `4840` (OPC UA TCP binary), `443` (HTTPS transport)

| Security Feature | Detail |
|---|---|
| **Authentication** | X.509 certificates (preferred) or username/password |
| **Message Signing** | Prevents tampering; detects MitM |
| **Encryption** | AES-256 for data in transit |
| **Authorization** | Role-based access (read-only, operator, admin) |
| **Auditing** | Security-relevant events logged |

**Security Modes — Critical to Understand:**
```
None            → No security at all (alarmingly common in production deployments)
Sign            → Integrity only — messages signed but NOT encrypted
Sign & Encrypt  → Full protection — recommended for all production use
```

> **Field Note (Aarti Industries):** Wonderware System Platform used OPC DA to pull data from Siemens PLCs into the Historian. The OPC server ran on Windows Server 2012 in Level 2. To make DCOM work, ports 135 and 49152–65535 had to be open on the host firewall — creating substantial lateral movement surface if the control network were ever breached from Level 3.

### OPC UA Attack Vectors
- `GetEndpoints` call reveals server capabilities unauthenticated
- Connecting with `SecurityMode = None` (no downgrade protection in old clients)
- Certificate spoofing if PKI is not properly implemented
- Node enumeration to map the full process data model without authorization
- Subscription abuse: subscribe to all nodes to exfiltrate complete process data

---

## DNP3

### Overview
DNP3 (Distributed Network Protocol 3) is the dominant protocol in **electric utilities** and **water/wastewater** for SCADA master ↔ RTU/IED communication over WAN links.

**Port:** `20000` (TCP/UDP)

### Key Protocol Features
| Feature | Description |
|---|---|
| **Time-stamping** | Events include timestamps — critical for incident reconstruction |
| **Unsolicited responses** | RTU can push data to master without being polled |
| **Integrity polling** | Periodic full-state sync between master and RTU |
| **Data link layer CRC** | Error detection for unreliable serial/radio links |
| **Data Objects** | Typed data (binary input, analog input, counter, control relay) |

### DNP3 Secure Authentication v5
Base DNP3 has zero security. SA v5 adds:
- HMAC-based challenge-response authentication
- Key management and update mechanism
- Critical: **still no encryption** — data visible in plaintext even with SA v5

### Attack Vectors
```
Replay Attack       — Capture valid "close breaker" command, replay later
Spoofing            — Inject commands impersonating SCADA master (no base auth)
Unauthorized Control — Send "Direct Operate" to open/close breakers or valves
Aurora Attack       — Rapidly cycle a breaker out-of-phase → generator physical destruction
Man-in-the-Middle   — Intercept and modify commands/responses on WAN links
```

### Aurora Vulnerability (Critical)
The Aurora generator test (Idaho National Laboratory, 2007) demonstrated that rapidly opening and closing a breaker out-of-phase with the generator can cause **physical destruction** of the generator through mechanical stress — purely through network commands.

---

## PROFINET

### Overview
Siemens industrial Ethernet standard for real-time PLC ↔ I/O communication. Dominant in European **discrete manufacturing** and Siemens-heavy process environments.

| Variant | Class | Cycle Time | Use Case |
|---|---|---|---|
| PROFINET RT | Real-Time | ~1ms | Standard I/O, process control |
| PROFINET IRT | Isochronous RT | ~31.25µs | Motion control, synchronization |

**Critical Network Property:** PROFINET runs at **Layer 2 (Ethernet frames)** — it is NOT TCP/IP routable. Cannot cross subnets without special handling.

### Security Concerns
```
❌ No authentication in PROFINET RT
❌ DCP (Discovery and Config Protocol) allows unauthenticated device enumeration and renaming
❌ S7comm (Siemens PLC programming protocol over PROFINET) allows unauthorized program read/write
❌ Siemens TIA Portal uses PROFINET for PLC programming — EWS compromise = PLC compromise
```

> **Field Note (Aarti Industries):** Siemens TIA Portal on the Engineering Workstation (EWS) communicated with S7-300 PLCs via PROFINET. Physical access to the EWS — or network access in Level 1 — provided the ability to download or modify PLC programs without any authentication prompt on the PLC itself.

### Siemens S7comm Security Note
S7comm (the proprietary protocol used by Siemens S7 PLCs) has known vulnerabilities:
- `S7comm-plus` (S7-1200/1500) has improved security but was broken by researchers
- `snap7` library allows unauthenticated read/write to S7-300/400 PLCs
- Stuxnet exploited S7comm to reprogram PLCs while hiding changes from TIA Portal

---

## EtherNet/IP

### Overview
Rockwell Automation / Allen-Bradley's industrial protocol. Uses **standard TCP/UDP** — fully routable, unlike PROFINET.

| Port | Type | Use |
|---|---|---|
| **44818** TCP | Explicit Messaging | Configuration, programming, diagnostics |
| **2222** UDP | Implicit Messaging | Real-time cyclic I/O data |

Uses **CIP (Common Industrial Protocol)** shared with DeviceNet and ControlNet.

### Security Concerns
```
❌ No authentication or encryption in base CIP
❌ CIP Identity Object reveals device info unauthenticated (model, vendor, serial, firmware)
❌ Unconnected messaging allows unsolicited data to any EtherNet/IP device
❌ CIP Safety (used in SIS applications) can be manipulated without auth on older devices
```

---

## Protocol Security Comparison

| Protocol | Port | Layer | Auth | Encryption | Sector |
|---|---|---|---|---|---|
| Modbus RTU | Serial | RS-485 | ❌ None | ❌ None | Universal |
| Modbus TCP | 502 | TCP | ❌ None | ❌ None | Universal |
| OPC DA | DCOM (dynamic) | Windows App | ⚠️ NTLM | ❌ None | Process industry |
| OPC UA | 4840 | TCP | ✅ X.509/Creds | ✅ AES-256 | Modern ICS |
| DNP3 | 20000 | TCP/UDP | ⚠️ SA v5 optional | ❌ None | Electric/Water |
| DNP3 SA v5 | 20000 | TCP/UDP | ✅ HMAC | ❌ None | Electric/Water |
| PROFINET RT | L2 Ethernet | Ethernet | ❌ None | ❌ None | Discrete mfg |
| EtherNet/IP | 44818/2222 | TCP/UDP | ❌ None | ❌ None | Rockwell PLCs |
| S7comm | 102 | TCP (ISO-TSAP) | ❌ None | ❌ None | Siemens PLCs |
| IEC 61850 GOOSE | L2 Multicast | Ethernet | ❌ None | ❌ None | Power substations |

---

## Wireshark Filters Cheatsheet

```bash
# ── MODBUS TCP ──────────────────────────────────────────────────
# All Modbus traffic
tcp.port == 502

# Only write commands (FC 5, 6, 15, 16) - potential manipulation
modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16

# Specific function code
modbus.func_code == 16

# Modbus errors (exception responses)
modbus.exception_code

# ── OPC UA ──────────────────────────────────────────────────────
tcp.port == 4840

# OPC UA with Security Mode None (insecure)
opcua.security_mode == 1

# ── DNP3 ────────────────────────────────────────────────────────
tcp.port == 20000 || dnp3

# DNP3 control relay output blocks (commands to field devices)
dnp3.al.obj == 12

# ── PROFINET ────────────────────────────────────────────────────
pn_dcp                          # Discovery and Configuration Protocol
pn_rt                           # PROFINET Real-Time

# ── ETHERNET/IP ─────────────────────────────────────────────────
tcp.port == 44818 || udp.port == 2222
enip                            # EtherNet/IP dissector

# ── SIEMENS S7COMM ──────────────────────────────────────────────
tcp.port == 102
s7comm

# S7 job requests (read/write PLC)
s7comm.param.func == 0x04       # Read variable
s7comm.param.func == 0x05       # Write variable

# ── USEFUL TSHARK COMMANDS ──────────────────────────────────────
# Enumerate all Modbus function codes in a capture
tshark -r capture.pcap -Y "tcp.port==502" -T fields -e modbus.func_code | sort | uniq -c

# Extract all Modbus register values being written
tshark -r capture.pcap -Y "modbus.func_code==16" -T fields -e modbus.regval_uint16

# Find all unique IPs talking Modbus
tshark -r capture.pcap -Y "tcp.port==502" -T fields -e ip.src -e ip.dst | sort -u

# Detect S7comm write operations (potential PLC reprogramming)
tshark -r capture.pcap -Y "s7comm.param.func==0x05" -T fields -e ip.src -e ip.dst
```

---

## Interview Q&A

**Q: Explain Modbus TCP and its critical security weaknesses.**
> Modbus TCP is a request-response protocol on port 502 that lets SCADA masters read and write data from PLCs and field devices. Its critical weakness is zero authentication, authorization, or encryption. Any host on the network can send Function Code 0x10 (Write Multiple Registers) to change critical process setpoints without any credential. This makes network segmentation and passive anomaly monitoring the primary defensive controls.

**Q: What is the difference between OPC Classic and OPC UA from a security perspective?**
> OPC Classic uses Windows DCOM, which requires opening large dynamic port ranges on firewalls, relies on NTLM (vulnerable to pass-the-hash), and has no data encryption. OPC UA was designed with security from the ground up — X.509 certificate authentication, AES-256 encryption, role-based access control, and platform independence. The critical issue in practice is that many OT deployments run OPC UA with SecurityMode=None for "compatibility," completely negating its security model.

**Q: Why is passive monitoring preferred over active scanning in OT networks?**
> Active scanners send probe packets that PLCs were never designed to receive. Legacy Siemens S7 PLCs and many RTUs can crash, enter fault states, or drop legitimate control traffic when they receive unexpected TCP connections or port scans. Passive monitoring — like Claroty or Dragos — only captures traffic already on the wire without injecting any packets, providing full asset visibility with zero operational risk.

**Q: What makes DNP3's Aurora vulnerability unique?**
> Aurora demonstrated that a purely cyber attack — sending legitimate DNP3 commands to cycle a circuit breaker rapidly out-of-phase with a generator — can cause permanent physical destruction of the generator through mechanical stress. This bridged the gap between cyber and kinetic effects and fundamentally changed how power sector security thought about OT threats.
