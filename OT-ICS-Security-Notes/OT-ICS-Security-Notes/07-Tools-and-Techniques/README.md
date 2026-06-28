# 07 - OT/ICS Security Tools and Techniques

## Passive Network Monitoring

### Why Passive-Only in OT
Active scanning tools (Nmap, Nessus) send unexpected packets that can crash PLCs, corrupt RTU memory, or disrupt industrial Ethernet timing. **Passive-only** techniques are mandatory in Level 0/1.

### Wireshark for OT Analysis

**Capture Setup (Passive)**
```bash
# Capture on SPAN/mirror port connected to OT switch
wireshark -i eth0 -k

# CLI capture with tshark
tshark -i eth0 -w /tmp/ot_capture.pcap

# Capture only OT protocols
tshark -i eth0 -f "port 502 or port 4840 or port 102 or port 20000" -w ot_only.pcap
```

**Essential Wireshark Display Filters for OT**
```
# Modbus
tcp.port == 502                          # All Modbus TCP
modbus.func_code == 16                   # Write Multiple Registers
modbus.func_code >= 5 && modbus.func_code <= 16  # All write operations

# OPC UA
tcp.port == 4840

# Siemens S7
tcp.port == 102
s7comm.param.func == 0x05               # Write variable

# DNP3
dnp3

# PROFINET
pn_dcp || pn_rt

# Find all unique hosts in a capture
(no display filter — use Statistics → Endpoints)
```

**tshark Analysis Commands**
```bash
# Enumerate all Modbus function codes in capture
tshark -r capture.pcap -Y "tcp.port==502" -T fields -e modbus.func_code | sort | uniq -c | sort -rn

# All unique IP pairs communicating over Modbus
tshark -r capture.pcap -Y "tcp.port==502" -T fields -e ip.src -e ip.dst | sort -u

# Extract Modbus register values being written
tshark -r capture.pcap -Y "modbus.func_code==16" -T fields -e ip.src -e modbus.regval_uint16

# Find all S7comm write operations
tshark -r capture.pcap -Y "s7comm.param.func==0x05" -T fields -e ip.src -e ip.dst -e frame.time

# Detect all devices on PROFINET DCP
tshark -r capture.pcap -Y "pn_dcp" -T fields -e pn_dcp.device_vendor -e pn_dcp.station_name

# Count connections by protocol
tshark -r capture.pcap -qz conv,tcp
```

---

## Asset Discovery (Passive)

### GrassMarlin (CISA Open Source)
```bash
# Install and run GrassMarlin
# Creates network topology from pcap — no active scanning
grassmarlin --pcap /path/to/capture.pcap
# Output: visual network map of all discovered OT devices with protocol info
```

### Python: Passive Modbus Device Identifier
```python
#!/usr/bin/env python3
"""
Passive Modbus Device Discovery
Reads a PCAP and extracts all Modbus devices, their slave IDs, and function codes seen
"""
from scapy.all import rdpcap, TCP
from collections import defaultdict

def analyze_modbus_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    devices = defaultdict(lambda: {"src_ips": set(), "func_codes": set()})
    
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].dport == 502:
            if len(pkt[TCP].payload) >= 8:
                payload = bytes(pkt[TCP].payload)
                try:
                    # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
                    unit_id = payload[6]
                    func_code = payload[7]
                    src_ip = pkt["IP"].src
                    dst_ip = pkt["IP"].dst
                    
                    key = f"{dst_ip}:slave_{unit_id}"
                    devices[key]["src_ips"].add(src_ip)
                    devices[key]["func_codes"].add(func_code)
                except (IndexError, KeyError):
                    pass
    
    print(f"\n{'='*60}")
    print(f"MODBUS DEVICES DISCOVERED (Passive)")
    print(f"{'='*60}")
    for device, info in devices.items():
        print(f"\nDevice: {device}")
        print(f"  Queried by: {', '.join(info['src_ips'])}")
        fc_names = {1:"ReadCoils", 2:"ReadDiscreteInputs", 3:"ReadHoldingRegs",
                    4:"ReadInputRegs", 5:"WriteCoil", 6:"WriteReg", 15:"WriteCoils",
                    16:"WriteRegs", 43:"DeviceID"}
        codes = [f"FC{c}({fc_names.get(c,'Unknown')})" for c in sorted(info['func_codes'])]
        print(f"  Function Codes: {', '.join(codes)}")
        if any(c in [5,6,15,16] for c in info['func_codes']):
            print(f"  ⚠️  WRITE OPERATIONS DETECTED")

if __name__ == "__main__":
    import sys
    analyze_modbus_pcap(sys.argv[1] if len(sys.argv) > 1 else "capture.pcap")
```

---

## OT-Specific Security Platforms

### Claroty Continuous Threat Detection (CTD)
- **Deployment:** Passive sensor on SPAN port; also active querying for Siemens/Rockwell (optional, tested)
- **Capabilities:** Asset inventory, protocol decoding (300+ OT protocols), vulnerability assessment, behavioral anomaly detection
- **Integration:** SIEM (Splunk, QRadar), ticketing, Active Directory
- **Use in interview:** "At Aarti, if we had deployed Claroty, it would have passively mapped all Siemens S7 and Modbus devices and baselined normal Wonderware↔PLC communication patterns."

### Dragos Platform
- **Focus:** Threat intelligence-led OT detection; ICS-specific threat behaviors
- **WorldView:** Threat intelligence feed with ICS-specific IOCs and TTPs
- **Playbooks:** Pre-built OT incident response playbooks
- **Known threats:** Dragos tracks 20+ ICS threat groups (Chernovite = Pipedream, Electrum = Industroyer)

### Nozomi Networks Guardian
- **Strength:** AI/ML-based anomaly detection; asset vulnerability scoring
- **Deployment:** Hardware sensor or virtual sensor on SPAN
- **Vantage:** Cloud-hosted dashboard for multi-site deployments

---

## PLC Security Testing Tools

> ⚠️ **ONLY use in lab/authorized environments. NEVER in production OT networks.**

### snap7 (Siemens S7 Communication Library)
```python
import snap7
from snap7.util import *

# Connect to Siemens S7-300/400 PLC (lab use only)
client = snap7.client.Client()
client.connect('192.168.1.10', 0, 1)  # IP, rack, slot

# Read DB1, starting at byte 0, reading 10 bytes
data = client.db_read(1, 0, 10)
print(f"DB1 data: {list(data)}")

# Write to DB1 (DANGEROUS - only in lab!)
# client.db_write(1, 0, bytearray([0x00, 0x01, 0x00, 0x00]))

client.disconnect()
```

### pymodbus (Modbus Lab Testing)
```python
from pymodbus.client import ModbusTcpClient

# Connect to Modbus slave (lab use only)
client = ModbusTcpClient('192.168.1.20', port=502)
client.connect()

# Read holding registers (FC 0x03)
result = client.read_holding_registers(0, 10, slave=1)
print(f"Registers: {result.registers}")

# Read device identification (FC 0x2B) - reconnaissance
result = client.read_device_information(slave=1)

client.close()
```

### mbtget (Modbus CLI)
```bash
# Read 10 holding registers from address 0
mbtget -a 0 -n 10 192.168.1.20

# Write to register (lab only!)
mbtset -a 100 -v 1234 192.168.1.20
```

---

## Shodan for OT Reconnaissance (Threat Intel / Red Team)

```bash
# Find internet-exposed Modbus TCP devices
shodan search "port:502 Modbus"

# Find Siemens S7 PLC on internet
shodan search "port:102 siemens"

# Find Wonderware HMI exposed online
shodan search "Wonderware InTouch"

# Find internet-exposed DNP3
shodan search "port:20000 dnp3"

# Geographic filter - OT devices in specific country
shodan search "port:502 country:IN"
```

**Use in security work:**
- Threat intel: check if client's assets are Shodan-indexed
- Attack surface: verify OT systems are NOT internet-accessible
- Research: understand what protocols are most exposed globally

---

## Zeek (Bro) for OT Protocol Monitoring

```bash
# Install Zeek with OT protocol support
sudo apt install zeek zeek-plugin-modbus zeek-plugin-dnp3 zeek-plugin-enip

# Run Zeek on SPAN port capture
zeek -i eth0 Protocols/ICS/modbus.zeek Protocols/ICS/dnp3.zeek

# Or analyze existing pcap
zeek -r ot_capture.pcap Protocols/ICS/modbus.zeek

# Generated logs:
# modbus.log    → all Modbus requests/responses with function codes
# dnp3.log      → all DNP3 messages
# conn.log      → all connections
```

**Zeek Modbus Log Fields:**
- `ts` — timestamp
- `uid` — connection ID  
- `id.orig_h/p` — client IP/port
- `id.resp_h/p` — server IP/port
- `func` — function code name ("READ_HOLDING_REGISTERS", "WRITE_REGISTERS")
- `request/response` — parsed request and response

---

## Malcolm (Idaho National Laboratory / CISA)

Malcolm is a full-featured network traffic analysis framework specifically designed for OT/ICS:
- **Arkime** (formerly Moloch) for packet capture and indexing
- **Zeek** for protocol analysis
- **Suricata** for signature-based detection
- **OpenSearch/Kibana** dashboards pre-configured for OT protocols
- Docker-based deployment

```bash
# GitHub: cisagov/Malcolm
git clone https://github.com/cisagov/Malcolm
cd Malcolm
python3 scripts/install.py
docker-compose up
# Access dashboard at https://localhost
```

---

## Interview Q&A

**Q: What tools would you use to monitor an OT network for threats without disrupting operations?**
> The core approach is passive monitoring only. I'd deploy a network TAP or SPAN port on the managed switch at Level 1/2 and feed that traffic to a passive monitoring platform. In a well-funded environment, that's Claroty or Dragos; in a resource-constrained setting, I'd use the open-source Malcolm framework (CISA/INL), which combines Zeek for protocol parsing, Suricata for detection, and OpenSearch for analysis. The key is establishing a behavioral baseline first — what devices exist, what they talk to, what function codes are normal — then alerting on deviations.

**Q: How would you use Wireshark to analyze a suspicious OT capture?**
> First, use Statistics → Protocol Hierarchy to understand what protocols are present. Then filter for OT protocols: `tcp.port == 502` for Modbus, `tcp.port == 102` for Siemens S7. I'd then look for write function codes — `modbus.func_code == 16` — and check whether the source IP is the expected SCADA master. Any writes from unexpected IPs or outside change windows are immediately suspicious. I'd also check for new devices by reviewing Statistics → Endpoints and comparing against the known asset inventory.

**Q: Have you used Shodan in your security work?**
> I've used Shodan for threat intelligence and attack surface validation. In an OT context, I'd use it to verify that a client's ICS assets are NOT indexed — port 502 (Modbus), 102 (Siemens S7), 44818 (EtherNet/IP), or 20000 (DNP3) should never appear on Shodan. Finding your own assets there is a critical finding requiring immediate firewall action. For threat intelligence, Shodan searches reveal the global scale of internet-exposed OT systems and help understand what attackers can see without even touching your network.
