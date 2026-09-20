# Enterprise Detection & Response: SOC Homelab

I built this virtualized Security Operations Center (SOC) to get hands-on experience with adversary emulation and detection engineering. Provisioned entirely through Vagrant, this environment models enterprise identity telemetry collection, custom Wazuh rule creation, and the validation of MITRE ATT&CK techniques.

---

## Architecture & Network Topology

| Host | Operating System | IP Address | Role / Description |
| :--- | :--- | :--- | :--- |
| **`wazuh-server`** | Ubuntu 22.04 LTS | `192.168.56.10` | Wazuh Manager, OpenSearch Indexer, & Web Dashboard |
| **`corp-dc01`** | Windows Server 2022 | `192.168.56.20` | Root Domain Controller (`corp.local`), Sysmon Agent |
| **`kali-attacker`** | Kali Linux Rolling | `192.168.56.30` | Adversary Emulation & Penetration Testing Node |

**Infrastructure Details:**
- **Virtualization:** Managed via Vagrant using VirtualBox host-only networking (`192.168.56.0/24`).
- **Telemetry Pipeline:** WinRM, Windows Event Channels, Sysmon v15 (with SwiftOnSecurity baseline), and Wazuh Agent 4.9.

---

## Project Milestones

- [x] Provisioned an isolated host-only network infrastructure via an automated `Vagrantfile`.
- [x] Deployed and optimized the Wazuh 4.9 stack, including kernel virtual memory tuning (`vm.max_map_count=262144`) and swap allocation.
- [x] Spun up Windows Server 2022 and promoted it to the Active Directory Forest root (`corp.local`).
- [x] Configured advanced auditing policies for Kerberos Ticket Operations and Windows Event logs.
- [x] Deployed Sysmon for granular process tracking and integrated the Wazuh agent to forward telemetry.
- [x] Verified cross-subnet routing and connectivity from the Kali Linux attack node.
- [x] Successfully emulated a Kerberoasting attack (**MITRE ATT&CK T1558.003**) using Impacket.
- [x] Engineered a custom Wazuh detection rule (`Rule ID: 100002`) to trigger high-severity alerts on RC4 (`0x17`) ticket encryption requests.

---

## Adversary Emulation & Detection Engineering

### The Attack: Kerberoasting (MITRE ATT&CK T1558.003)
- **Tactic:** Credential Access (TA0006)
- **Technique:** Steal or Forge Kerberos Tickets (T1558.003)
- **Execution:** Authenticating as a standard domain user (`corp.local\vagrant`) from the Kali node, I requested a Ticket Granting Service (TGS) ticket for the service principal `MSSQLSvc/dc01.corp.local:1433`. The request intentionally forced legacy RC4-HMAC encryption to extract a crackable ticket hash.

### Custom Detection Logic (`local_rules.xml`)
By default, Windows logging treats Kerberos ticket requests as normal operational traffic. To surface this adversary activity, I wrote a custom high-severity detection rule on the Wazuh Manager to flag RC4 downgrade requests:

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

```

### 1. Wazuh SIEM Dashboard Deployment
![Wazuh Dashboard Active](01_wazuh_dashboard_active.png)

### 2. Active Directory Domain Controller Promotion
![AD Domain Controller Promoted](02_ad_domain_controller_promoted.png)

### 3. Wazuh Agent Telemetry Integration
![Wazuh Agent Active](03_wazuh_agent_active.png)

### 4. Sysmon Telemetry Stream Analysis
![Sysmon Telemetry Stream](04_sysmon_telemetry_stream.png)

### 5. Kerberoasting Attack Execution (Impacket)
![Kali Kerberoast Hash](05_kali_kerberoast_hash.png)

### 6. Wazuh Custom Rule Detection (Event ID 4769)
![Wazuh Event 4769 Detection](06_wazuh_event_4769_detection.png)
