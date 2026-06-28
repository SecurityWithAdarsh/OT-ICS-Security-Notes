# 09 - OT/ICS Case Studies

## 1. Stuxnet (2010)

**Target:** Natanz Uranium Enrichment Facility, Iran  
**Goal:** Physically destroy centrifuges while evading detection  
**Attribution:** US/Israel (not officially confirmed)

### Attack Chain
1. Spread via infected USB drives (exploited 4 Windows zero-days)
2. Searched for systems running Siemens WinCC/Step7 SCADA software
3. Installed Siemens S7 PLC rootkit via Step7 OPC server
4. Identified specific PLC model (S7-315/417) and centrifuge motor config
5. Modified centrifuge spin profiles (too fast → too slow repeatedly)
6. Intercepted legitimate monitoring data → fed false "normal" readings to HMI
7. Disabled Safety Instrumented System (SIS) to prevent emergency shutdown

### Impact
- ~1,000 of ~5,000 Natanz centrifuges physically destroyed
- Iranian nuclear program set back 1–2 years (estimated)
- First publicly confirmed cyberweapon causing physical destruction

### MITRE ATT&CK for ICS Mapping
- T0862: Unauthorized Command Message
- T0857: System Firmware (PLC rootkit)
- T0855: Inhibit Response Function (SIS disabled)
- T0816: Loss of View (false sensor data to HMI)
- T0865: Spearphishing Attachment (initial USB vector)

### Key Lessons
- Air gaps alone are insufficient (USB bridged the gap)
- SIS independence is critical — must be truly separate from DCS
- Rootkits can hide malicious PLC code from engineering tools
- Sophisticated attackers research target physics before deploying

---

## 2. TRITON / TRISIS (2017)

**Target:** Petro Rabigh petrochemical facility, Saudi Arabia  
**System Targeted:** Schneider Electric Triconex Safety Instrumented System  
**Goal:** Disable safety systems to enable a catastrophic physical event  
**Attribution:** Sandworm (Russia) — per Mandiant/Dragos research

### Attack Chain
1. IT network compromised (initial vector not fully disclosed)
2. Lateral movement to OT — reached engineering workstation in Level 3
3. Deployed TRITON framework targeting Triconex TSCP protocol
4. Attempted to reprogram SIS logic to disable safety functions
5. A bug in the malware caused two SIS controllers to enter "fail safe" state
6. Unplanned plant shutdown triggered — attack discovered

### Technical Details
TRITON consisted of:
- `triton.py` — main attack framework communicating via TriStation protocol
- `imain.bin` — malicious ladder logic payload for Triconex controller
- `inject.bin` — payload injector
- Communicated via TriStation protocol (UDP 1502) — proprietary Triconex protocol

### Impact
- Near-miss: If successful, an undetected SIS failure followed by a process upset could have caused explosion, fire, mass casualties
- Discovered accidentally (not by security monitoring)
- No physical damage occurred due to the bug

### Significance
First publicly known malware specifically targeting a Safety Instrumented System — crossing from process disruption to potential mass casualty.

### Key Lessons
- SIS systems are now explicit attacker targets
- SIS must be physically isolated (separate air-gapped network, not just VLAN)
- TriStation protocol was undocumented but attackers reverse-engineered it
- Detection was accidental — not from any security control

---

## 3. Ukraine Power Grid Attacks (2015 & 2016)

### 2015 Attack (BlackEnergy / Sandworm)
**Target:** Three Ukrainian distribution companies  
**Impact:** ~225,000 customers, 1–6 hours without power

**Attack Chain:**
1. Spearphishing emails with malicious Excel macros to employees
2. BlackEnergy malware installed; credential harvesting
3. 6-month reconnaissance of SCADA systems
4. Attackers manually opened circuit breakers via legitimate HMI access (30 substations)
5. Overwrote UPS firmware to extend outage
6. Flooded customer call center with calls (telephony DoS)
7. Deployed KillDisk wiper to destroy workstations and prevent recovery

### 2016 Attack (Industroyer / CrashOverride / Sandworm)
**Target:** Ukrenergo transmission substation  
**Impact:** ~225,000 customers, ~1 hour (smaller but more automated)

**Technical Innovation: ICS Protocol Modules**
Industroyer contained native OT protocol modules:
```
Module 1: IEC 61850 — Substation automation
Module 2: IEC 60870-5-101 — Serial SCADA protocol
Module 3: IEC 60870-5-104 — TCP SCADA protocol
Module 4: DNP3 — Used in some substations
Module 5: OPC DA — Process data access
```
The malware automatically communicated in these protocols without human operators.

Additional components:
- DoS component against Siemens SIPROTEC protective relays (wiper)
- Data wiper to remove forensic evidence

### Key Lessons
- Nation-state actors conduct extended (6+ month) reconnaissance before attacking
- Manual operator sessions are nearly undetectable from legitimate activity
- Industroyer showed attackers now develop ICS protocol expertise
- Wipers are used to destroy evidence and hinder recovery
- Both attacks started with IT compromise (spearphishing) → OT lateral movement

---

## 4. Colonial Pipeline (2021)

**Target:** Colonial Pipeline Company, largest US fuel pipeline  
**Mechanism:** DarkSide ransomware on IT billing systems  
**Impact:** Voluntary OT shutdown, US East Coast fuel shortage, $4.4M ransom

### Important Distinction
The OT pipeline was **NOT directly compromised.** Colonial shut down OT operations **out of caution** to prevent potential ransomware spread to OT systems.

### Attack Chain
1. DarkSide gained access via a compromised VPN account with no MFA
2. Ransomware deployed across Colonial's IT network
3. Billing and accounting systems encrypted
4. Colonial voluntarily shut down OT pipeline operations
5. Fuel shortages in Southeast US; panic buying
6. Colonial paid $4.4M ransom; recovered ~$2.3M via FBI

### Key Lessons
- **MFA on VPN is non-negotiable** — a single credential was the entire entry point
- IT ransomware can cause OT operational impact even without touching OT
- Business decisions (voluntary shutdown) can amplify cyber incident impact
- Colonial's OT/IT segmentation was apparently adequate (no OT compromise)
- Paying ransom does not guarantee quick recovery

---

## 5. Oldsmar Water Treatment Plant (2021)

**Target:** City of Oldsmar water treatment plant, Florida  
**Method:** Remote HMI access via TeamViewer  
**Goal:** Increase sodium hydroxide to dangerous levels

### Attack Chain
1. Attacker accessed the plant via TeamViewer (legitimate remote access tool)
2. Entry used either old credentials or password found in data breach
3. Attacker moved the sodium hydroxide setpoint from 111 ppm to 11,100 ppm (100x)
4. A plant operator saw the cursor moving on his screen and reversed the change immediately
5. Attack failed due to human intervention; no harm to water supply

### Key Lessons
- **Direct internet-facing remote access to OT is unacceptable** — TeamViewer should not be internet-exposed to control systems
- **No MFA** on remote access enabled this attack
- **Operator vigilance** was the only control that worked
- Proper architecture: remote access only via DMZ jump server with MFA and session recording

---

## 6. Maroochy Shire Sewage Attack (2000)

**Target:** Queensland, Australia water utility (sewage system)  
**Actor:** Vitek Boden — disgruntled former contractor

### Attack Chain
1. Boden was rejected for a job at the utility after completing the SCADA installation
2. He had legitimate radio equipment and knowledge of the system
3. Used stolen SCADA transmitter + laptop to send unauthorized radio commands to RTUs
4. Sent 46 separate attacks over 2 months, causing raw sewage releases
5. 800,000 liters of raw sewage released into local parks, waterways, hotel grounds

### Significance
- First confirmed case of a **malicious insider** exploiting ICS knowledge for environmental damage
- Demonstrated that physical knowledge + technical access = OT attack capability
- Radio-based access bypassed all network controls

### Key Lessons
- Insider threat is a primary OT risk vector
- Terminate contractor access immediately after engagement ends
- Audit who has physical/radio access to OT systems
- Radio-based SCADA requires authentication on control messages

---

## Comparative Analysis

| Incident | Initial Vector | Target System | Impact Type | Detection Method |
|---|---|---|---|---|
| Stuxnet | USB | Siemens S7 PLC | Physical destruction | External (Kaspersky research) |
| TRITON | IT compromise | Triconex SIS | Near-miss safety event | Accidental (SIS fault) |
| Ukraine 2015 | Spearphishing | Distribution SCADA | Power outage | Operations (outage) |
| Ukraine 2016 | Unknown | Transmission SCADA | Power outage | Operations (outage) |
| Colonial | VPN credentials | IT (billing) | Voluntary OT shutdown | IT security alert |
| Oldsmar | TeamViewer | Water HMI | Near-miss chemical | Operator visual |
| Maroochy | Radio/insider | Water RTUs | Sewage release | Investigation |

---

## Interview Q&A

**Q: What is the most significant lesson from Stuxnet for OT security practitioners?**
> Stuxnet demonstrated that air gaps alone are insufficient — USB drives bridged the gap. It showed that sophisticated attackers will invest in deep ICS domain knowledge (they understood Siemens centrifuge physics). Most importantly, it showed that attackers will target the SIS to prevent safety systems from responding. This means SIS must be physically isolated, not just logically separated, and all OT environments need USB controls regardless of network isolation.

**Q: Why is TRITON considered the most dangerous ICS malware ever discovered?**
> Because it explicitly targeted the last line of defense — the Safety Instrumented System. Previous attacks disrupted operations; TRITON aimed to disable the system whose sole purpose is preventing catastrophic physical events (explosions, fires, toxic releases). Its discovery was accidental. If the bug hadn't caused the SIS to fail safe, the attackers would have succeeded in creating conditions where a process upset could have caused mass casualties without the SIS intervening.
