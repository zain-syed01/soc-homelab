# Enterprise Detection & Response Security Operations Homelab

A fully virtualized Security Operations Center (SOC) and adversary emulation environment built with Vagrant, VirtualBox, Active Directory, and Wazuh SIEM. This project models enterprise identity telemetry collection, detection engineering via custom XML rules, and MITRE ATT&CK technique validation.

---

## Architecture & Network Topology

| Host | Operating System | IP Address | Role / Description |
| :--- | :--- | :--- | :--- |
| **`wazuh-server`** | Ubuntu 22.04 LTS | `192.168.56.10` | Wazuh Manager, OpenSearch Indexer, & Web Dashboard |
| **`corp-dc01`** | Windows Server 2022 | `192.168.56.20` | Root Domain Controller (`corp.local`), Sysmon Telemetry Agent |
| **`kali-attacker`** | Kali Linux Rolling | `192.168.56.30` | Adversary Emulation & Penetration Testing Node |

- **Virtualization & Automation:** Managed using Vagrant with VirtualBox host-only networking (`192.168.56.0/24`).
- **Telemetry Pipelines:** WinRM, Windows Event Channel, Sysmon v15 (SwiftOnSecurity configuration), and Wazuh Agent 4.9.

---

##  Implementation Milestones

- [x] Provisioned isolated host-only network infrastructure via automated `Vagrantfile`.
- [x] Deployed and optimized Wazuh 4.9 stack (kernel virtual memory tuning `vm.max_map_count=262144` and swap allocation).
- [x] Provisioned Windows Server 2022 and promoted to Active Directory Forest root (`corp.local`).
- [x] Configured advanced auditing policies for Kerberos Ticket Operations and Windows Event Channels.
- [x] Deployed Sysmon with SwiftOnSecurity detection configuration and integrated the Wazuh agent.
- [x] Deployed Kali Linux attack node and verified cross-subnet routing.
- [x] Emulated Kerberoasting attack (**MITRE ATT&CK T1558.003**) using Impacket.
- [x] Authored custom Wazuh detection rule (`Rule ID: 100002`) alerting on RC4 (`0x17`) ticket encryption requests.

---

## 🔍 Adversary Emulation & Detection Engineering

### Scenario: Kerberoasting (MITRE ATT&CK T1558.003)
- **Tactic:** Credential Access (TA0006)
- **Technique:** Steal or Forge Kerberos Tickets (T1558.003)
- **Adversary Action:** Authenticated as a standard domain user (`corp.local\vagrant`) from `192.168.56.30` and requested a Ticket Granting Service (TGS) ticket for service principal `MSSQLSvc/dc01.corp.local:1433` using legacy RC4-HMAC encryption.

### Custom Detection Logic (`local_rules.xml`)
Standard Windows logging treats Kerberos ticket requests as normal operational traffic. To surface adversary activity, a custom high-severity detection rule was implemented on the Wazuh Manager:

```xml
<rule id="100002" level="10">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <description>Possible Kerberoasting: Kerberos Service Ticket requested with RC4 (0x17) for $(win.eventdata.serviceName)</description>
  <mitre>
    <id>T1558.003</id>
  </mitre>
</rule>


📸 Telemetry & Detection Evidence
Wazuh SIEM Management Dashboard


Active Directory Domain Controller Promotion


Active Endpoint Telemetry Link


Impacket Kerberoasting Ticket Extraction (Kali Linux)


Wazuh Detection Trigger (Rule 100002 - Level 10)
