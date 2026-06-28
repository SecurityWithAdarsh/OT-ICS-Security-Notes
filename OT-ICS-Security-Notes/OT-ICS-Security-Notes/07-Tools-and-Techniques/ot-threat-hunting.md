# OT Threat Hunting Playbook

## Hypothesis-Driven Hunting in OT

Unlike IT threat hunting, OT hunting must be:
- **Passive only** — no active probing
- **Process-aware** — understand what "normal" looks like for THIS plant
- **Safety-first** — hunting activities cannot impact operational continuity

---

## Hunt 1: Unauthorized Engineering Activity

**Hypothesis:** An attacker has gained access to an Engineering Workstation or is impersonating one.

**Data Sources:** Network traffic (SPAN), SCADA historian, Windows event logs (if available)

**Hunting Queries (Zeek/tshark)**
```bash
# Find all S7comm connections (Siemens PLC programming)
# Expected: only from EWS IP (e.g., 192.168.30.50) during business hours
tshark -r capture.pcap -Y "tcp.port==102" -T fields \
  -e frame.time -e ip.src -e ip.dst | sort -u

# Flag: Any source IP other than EWS, or connections at unusual hours

# Find all Modbus write operations and their sources
tshark -r capture.pcap \
  -Y "modbus.func_code==5 || modbus.func_code==6 || modbus.func_code==15 || modbus.func_code==16" \
  -T fields -e frame.time -e ip.src -e ip.dst -e modbus.func_code

# Flag: Write operations from any IP not in the authorized master list
```

**Zeek Analysis**
```bash
# Zeek modbus.log — look for writes from unexpected sources
cat modbus.log | zeek-cut ts id.orig_h id.resp_h func | \
  awk '$4 ~ /WRITE/ {print}' | sort -u

# Look for new communication pairs never seen before
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p | \
  sort -u > current_connections.txt
# Compare against baseline_connections.txt
diff baseline_connections.txt current_connections.txt
```

**SCADA Historian Check**
- Pull historian trend for "PLC communication fault" or "scan cycle" tags
- Programming activity from EWS appears as brief PLC scan cycle interruption
- Unexpected dips in scan cycle at odd hours = potential unauthorized programming

---

## Hunt 2: New Device on OT Network

**Hypothesis:** An unauthorized device has been connected to the OT network.

**Hunting Queries**
```bash
# Extract all unique MAC addresses seen in a capture period
tshark -r capture.pcap -T fields -e eth.src | sort -u > current_macs.txt
tshark -r capture.pcap -T fields -e eth.dst | sort -u >> current_macs.txt
sort -u current_macs.txt > current_macs_sorted.txt

# Compare against approved device inventory
# Any MAC not in approved list = unknown device
comm -23 current_macs_sorted.txt approved_macs.txt

# Find all new IPs compared to baseline
tshark -r capture.pcap -T fields -e ip.src | sort -u > current_ips.txt
comm -23 current_ips.txt baseline_ips.txt
```

**Python: MAC OUI Lookup for Unknown Devices**
```python
import requests

def lookup_oui(mac):
    """Look up vendor from MAC OUI"""
    oui = mac.replace(':', '').replace('-', '')[:6].upper()
    try:
        r = requests.get(f"https://api.macvendors.com/{oui}", timeout=3)
        return r.text if r.status_code == 200 else "Unknown"
    except:
        return "Lookup failed"

unknown_macs = [
    "00:1B:44:11:3A:B7",   # Example unknown MACs from analysis
    "DC:A6:32:00:AB:CD",
]

print("Unknown Device Vendor Lookup:")
for mac in unknown_macs:
    vendor = lookup_oui(mac)
    print(f"  {mac} → {vendor}")
```

**What to do with unknown devices:**
1. Check physical connections — was maintenance done recently? USB-to-Ethernet adapters?
2. Check DHCP server logs for when the IP was first assigned
3. Escalate to OT engineer for physical verification
4. Block MAC at switch level while investigating

---

## Hunt 3: Lateral Movement from IT to OT

**Hypothesis:** An attacker has moved from the IT/corporate network into the OT DMZ or control network.

**Hunting Queries**
```bash
# Look for connections originating from corporate IP range to OT subnets
# Corporate: 10.0.0.0/8, OT: 192.168.0.0/16
tshark -r capture.pcap \
  -Y "ip.src >= 10.0.0.0 && ip.src <= 10.255.255.255 && ip.dst >= 192.168.0.0" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport | sort -u

# Look for RDP connections (3389) from unexpected sources to OT
tshark -r capture.pcap -Y "tcp.port==3389" \
  -T fields -e ip.src -e ip.dst | sort -u

# Look for connections to EWS from any source other than Jump Server
JUMP_SERVER="192.168.20.30"
EWS_IP="192.168.30.50"
tshark -r capture.pcap \
  -Y "ip.dst==$EWS_IP && ip.src!=$JUMP_SERVER && tcp.port==3389"
```

**Firewall Log Analysis**
```bash
# Extract allowed flows through OT perimeter firewall during incident window
grep "PERMIT" /var/log/firewall.log | grep -v "known_authorized_flows" | \
  awk '{print $5, $7, $9, $11}' | sort -u
# Flag: Any permitted connection not matching the documented conduit ruleset
```

---

## Hunt 4: False Data Injection Detection

**Hypothesis:** An attacker is feeding false data to SCADA to mask a physical anomaly.

**Approach:** Compare network-observed register values against historian values for the same time period.

```python
#!/usr/bin/env python3
"""
Detect potential false data injection by comparing:
- Modbus register values seen on wire (from pcap)
- Historian values for same time/tag
"""
from scapy.all import rdpcap, TCP
import struct
from datetime import datetime

def extract_modbus_fc03_values(pcap_file, target_slave_ip, start_register, count):
    """Extract FC03 response values from a pcap"""
    packets = rdpcap(pcap_file)
    timeline = []
    
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer('IP')):
            continue
        if pkt['IP'].src != target_slave_ip:  # Only PLC responses
            continue
        if pkt[TCP].sport != 502:
            continue
        
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 9:
            continue
        
        func_code = payload[7]
        if func_code != 3:  # FC03 response
            continue
        
        byte_count = payload[8]
        reg_values = []
        for i in range(0, byte_count, 2):
            if 9 + i + 1 < len(payload):
                value = struct.unpack('>H', payload[9+i:9+i+2])[0]
                reg_values.append(value)
        
        timestamp = float(pkt.time)
        timeline.append({
            "time": datetime.fromtimestamp(timestamp),
            "registers": reg_values
        })
    
    return timeline

# Usage
wire_values = extract_modbus_fc03_values(
    "capture.pcap",
    target_slave_ip="192.168.1.10",
    start_register=30001,  # Input registers (sensor readings)
    count=10
)

print("Wire-observed register values:")
for entry in wire_values[-5:]:  # Last 5 readings
    print(f"  {entry['time']} → {entry['registers']}")

print("\nCompare these against historian tag values for same time window.")
print("Significant discrepancy = potential false data injection.")
```

---

## Hunt 5: TRITON-Pattern Detection (Safety System Targeting)

**Hypothesis:** An attacker is probing or communicating with the Safety Instrumented System.

```bash
# Detect TriStation protocol (Triconex SIS) traffic on UDP 1502
# Any traffic to SIS network from unexpected source is critical alert
tshark -r capture.pcap -Y "udp.port==1502" \
  -T fields -e frame.time -e ip.src -e ip.dst

# Monitor for any connections TO the SIS subnet from non-engineering IPs
SIS_SUBNET="192.168.60.0/24"  # SIS should be isolated
EWS_IP="192.168.30.50"

# Any traffic to SIS from anything other than EWS = CRITICAL
tshark -r capture.pcap \
  -Y "ip.dst net 192.168.60.0/24 && ip.src != 192.168.30.50" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport

# This should return zero results in a properly segmented environment
# Any result is a Priority 1 incident
```

---

## Threat Hunting Workflow Summary

```
1. DEFINE HYPOTHESIS
   Based on threat intel, known TTPs, anomalies reported by operations

2. COLLECT DATA
   SPAN port capture, SCADA historian export, firewall logs, EWS event logs

3. ESTABLISH BASELINE
   What is normal for THIS specific OT environment?
   - Authorized device list (IP + MAC)
   - Authorized communication pairs
   - Normal function codes per master/slave pair
   - Normal register value ranges (from historian)

4. HUNT
   Look for deviations from baseline
   New devices, new connections, unusual function codes, value anomalies

5. INVESTIGATE POSITIVES
   Coordinate with OT engineer: is there a legitimate explanation?
   (e.g., maintenance that wasn't communicated to security)

6. ESCALATE CONFIRMED THREATS
   Follow OT IR playbook (see 08-Incident-Response)

7. UPDATE DETECTIONS
   Turn confirmed TTPs into ongoing detection rules in OT IDS
```
