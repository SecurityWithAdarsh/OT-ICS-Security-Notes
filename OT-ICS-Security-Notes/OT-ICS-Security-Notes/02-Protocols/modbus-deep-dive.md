# Modbus Protocol — Deep Dive

## Packet Structure

### Modbus TCP Frame
```
┌──────────────────────────────────────────────────────────┐
│                    TCP/IP Header                          │
├────────────┬─────────────┬───────────┬────────────────────┤
│Transaction │ Protocol ID │  Length   │  Unit ID  │ PDU    │
│   ID (2B)  │   (2B)=0x00 │   (2B)   │   (1B)    │        │
├────────────┴─────────────┴───────────┴────────────────────┤
│ MBAP Header (7 bytes)              │ Modbus PDU           │
└────────────────────────────────────┴──────────────────────┘

PDU = Function Code (1B) + Data (N bytes)
```

### Example: Read Holding Registers (FC 03) Request
```
Bytes:  00 01  00 00  00 06  01  03  00 00  00 0A
        ──────  ──────  ──────  ──  ──  ──────  ──────
        Trans   Proto   Len    UID FC  Start   Count
        ID      ID=0    =6     =1  =3  Addr=0  =10 regs
```

### Example: Write Multiple Registers (FC 16) Request
```
Bytes:  00 02  00 00  00 0F  01  10  00 64  00 02  04  01 90  00 FA
        Trans  Proto  Len    UID FC  Start  Count  ByteCnt  Reg1  Reg2
        ID     ID     =15    =1  =16 =100   =2     =4       =400  =250
```
→ Writing value 400 and 250 to registers starting at address 100 on slave 1

## Python: Modbus Traffic Analyzer
```python
#!/usr/bin/env python3
"""
Real-time Modbus TCP anomaly detector
Alerts on write operations from unexpected source IPs
"""
from scapy.all import sniff, TCP, IP
import datetime

AUTHORIZED_MASTERS = {"192.168.2.10", "192.168.2.11"}  # SCADA master IPs
WRITE_FUNCTION_CODES = {5, 6, 15, 16}

def analyze_modbus(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
        return
    if pkt[TCP].dport != 502:
        return
    payload = bytes(pkt[TCP].payload)
    if len(payload) < 8:
        return
    
    try:
        func_code = payload[7]
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if func_code in WRITE_FUNCTION_CODES:
            alert_level = "⚠️  WRITE" if src_ip in AUTHORIZED_MASTERS else "🚨 UNAUTHORIZED WRITE"
            print(f"[{timestamp}] {alert_level} | FC:{func_code} | {src_ip} → {dst_ip}")
            
            if src_ip not in AUTHORIZED_MASTERS:
                print(f"    ACTION REQUIRED: Unauthorized source attempting Modbus write!")
    except (IndexError, Exception):
        pass

print("Modbus Anomaly Detector running on port 502...")
print(f"Authorized masters: {AUTHORIZED_MASTERS}")
sniff(filter="tcp port 502", prn=analyze_modbus, store=0)
```
