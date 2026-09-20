# Detection & Response Security Operations Lab

## Architecture & Nodes
- **SIEM / Telemetry Engine:** Wazuh 4.9 All-in-One (Ubuntu 22.04 LTS) — `192.168.56.10`
- **Domain Controller / Identity Target:** Windows Server 2022 (`dc01`) — `192.168.56.20`
- **Attacker Node:** Kali Linux Rolling — `192.168.56.30`

## Implementation Milestones
- [x] Automated provisioning of Wazuh SIEM stack via Vagrant + VirtualBox
- [x] Configured memory limits (`vm.max_map_count`) and swap allocation for OpenSearch indexer cluster
- [x] Deployed Wazuh Indexer, Manager, and Dashboard services
- [ ] Active Directory Domain Controller deployment & telemetry pipeline
- [ ] Sysmon and Wazuh agent endpoint deployment