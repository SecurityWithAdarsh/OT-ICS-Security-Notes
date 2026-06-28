# ICS Components Glossary

> A reference guide to every major component in an Industrial Control System. Knowing the hardware is essential — attacks target specific components, and defenses must account for their constraints.

---

## Control Devices

### PLC — Programmable Logic Controller
The workhorse of industrial automation. A ruggedized digital computer that reads inputs (sensors, switches), executes a control program (ladder logic, function block, structured text), and drives outputs (actuators, motors, valves).

- **Scan cycle**: PLC reads all inputs → executes program → writes all outputs → repeats. Typical cycle: 1–100ms.
- **Security concern**: Most PLCs have no authentication. An attacker on the network can send commands directly. Firmware modification is possible on some models.
- **Vendors**: Siemens (S7 series), Rockwell Allen-Bradley (ControlLogix), Schneider Electric (Modicon), Mitsubishi, Omron.
- **Famous attack target**: Stuxnet targeted Siemens S7-315 and S7-417 PLCs.

### RTU — Remote Terminal Unit
Similar to a PLC but designed for **geographically distributed** deployments — oil pipelines, water treatment, power substations. Communicates back to a central SCADA server over long-distance links (radio, cellular, satellite).

- Designed for harsh environments, low bandwidth
- Often uses DNP3 or IEC 60870-5-101/104 protocols
- Less processing power than modern PLCs

### DCS — Distributed Control System
A control system architecture designed for **continuous process control** (refineries, chemical plants, power generation). Unlike PLCs which are standalone, a DCS is tightly integrated — controllers, I/O modules, historian, and HMI are all from the same vendor.

- **Examples**: Honeywell Experion, ABB 800xA, Emerson DeltaV, Yokogawa CENTUM
- DCS controllers typically talk on a proprietary backplane bus
- Security concern: vendor-specific interfaces that IT teams don't understand

---

## Human-Machine Interfaces

### HMI — Human Machine Interface
The operator screen. Displays real-time process data (temperatures, pressures, flow rates, valve positions) and allows operators to issue commands.

- **Types**: Panel PCs, industrial touchscreens, SCADA client workstations
- Almost always runs **Windows** (often legacy: XP, 7)
- Directly connected to PLCs/DCS — compromise gives process control
- Security concern: USB ports, internet connectivity for remote support

### SCADA — Supervisory Control and Data Acquisition
A software system (and architecture pattern) for monitoring and controlling geographically dispersed assets. Think of it as the brain above the PLCs.

- Collects data from RTUs/PLCs via protocols (DNP3, Modbus, OPC)
- Provides centralized visibility and alarm management
- **Not the same as DCS**: SCADA = geographically distributed, DCS = co-located process plant
- Examples: Wonderware (AVEVA), Ignition (Inductive Automation), GE iFIX, Siemens WinCC

---

## Field Devices

### Sensor
Converts a physical quantity into an electrical signal.
- **Types**: Temperature (thermocouple, RTD), pressure (pressure transmitter), flow (Coriolis, magnetic), level (ultrasonic, radar), analytical (pH, conductivity)
- Security concern: sensors can be spoofed (false data injection) to mislead control logic

### Actuator
Converts a control signal into physical action.
- **Types**: Control valves, on/off valves, variable frequency drives (VFDs), pumps, conveyors
- A compromised actuator can cause physical damage — opening a valve at wrong time, spinning a motor to destruction

### Transmitter
A field device that reads a sensor and transmits a standardized signal (4-20mA current loop, HART, Foundation Fieldbus) back to the controller.

### Field Bus
Industrial communication networks that replace point-to-point wiring between field devices and controllers.
- **Examples**: Foundation Fieldbus, PROFIBUS, DeviceNet, AS-Interface
- Security concern: many field buses have no encryption or authentication

---

## Historian and Data Infrastructure

### Historian
A specialized time-series database that stores all process data. Sits between OT and IT networks — a **classic convergence point**.

- **Examples**: OSIsoft PI System (most common), Honeywell PHD, AspenTech IP.21
- Stores millions of tag values (e.g., every temperature reading every second)
- Used for process optimization, maintenance, regulatory compliance
- Security concern: Historian servers are frequently the bridge between OT and IT — compromise can be a pivot point

### EWS — Engineering Workstation
The laptop or PC used by control engineers to develop PLC programs, configure devices, and deploy updates. Has access to every device on the OT network.

- **Extremely high-value target** — full access to all control devices
- Often used intermittently; sometimes connected to both OT and IT networks
- Used by vendors via remote access (high-risk)

---

## Network Infrastructure

### Industrial Firewall / Data Diode
Firewalls adapted for OT protocol awareness (Modbus, DNP3, OPC awareness). Data diodes enforce one-way communication (OT → IT only, hardware-enforced).
- **Vendors**: Fortinet FortiGate, Palo Alto, Waterfall Security (data diodes)

### Jump Server / Jump Host
A hardened intermediate server that provides controlled access to the OT network. Remote maintenance must go through the jump server.

### DMZ (OT)
A demilitarized zone between IT and OT. Hosts shared services (historian, file transfer servers, remote access gateways) that both networks need to reach.

---

## Safety Systems

### SIS — Safety Instrumented System
An independent layer of protection designed to detect hazardous conditions and take the process to a safe state automatically, **independent of the control system**.

- **Standard**: IEC 61511 (SIS standard for process industry)
- Monitors critical variables (pressure, temperature, level)
- Takes automatic safe action: closes valves, shuts down pumps, triggers alarms
- **Must be physically and logically separate from the DCS/PLC**
- **TRITON/TRISIS (2017)**: Nation-state malware specifically targeting Schneider Electric Triconex SIS controllers

### ESD — Emergency Shutdown System
A subset of SIS. Specifically handles plant-wide or unit emergency shutdowns.

### Fire & Gas Detection System
Detects fire, smoke, combustible gas, and toxic gas. Triggers alarms, activates suppression systems. Often integrated with SIS.

---

## Quick Reference Card

| Component | Function | Primary Security Risk |
|---|---|---|
| PLC | Controls field devices | No auth; direct command injection |
| RTU | Remote monitoring/control | Long-range comms, often unencrypted |
| DCS | Continuous process control | Proprietary, hard to monitor |
| HMI | Operator interface | Legacy Windows, USB vectors |
| SCADA | Supervisory/data collection | Internet exposure, credential attack |
| Historian | Time-series data storage | IT-OT bridge; pivot point |
| EWS | Engineering access | Highest-privilege; vendor access |
| SIS | Safety enforcement | Physical safety consequence if compromised |

---

*Next: [Safety vs Security →](Safety-vs-Security.md)*
