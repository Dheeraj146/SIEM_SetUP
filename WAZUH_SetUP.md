# Wazuh — Complete Guide & Deployment Playbook

## Overview 
- Wazuh is an open-source SIEM/HIDS/XDR platform that centralizes endpoint telemetry, detects threats, automates response, and supports compliance programs. This repo documents architecture, features, IDS/IPS/EDR context, a single-node Ubuntu deployment, integration patterns (SentinelOne, Suricata), scaling guidance, hardening checklists, SOC playbooks, and troubleshooting. 

|Table of Contents|
|-----------------|
|TL;DR — Who, Why, and When to use Wazuh|

|Core Concepts & Terminology (SIEM, HIDS, HIPS, EDR, FIM, Indexer, Decoders, Rules)|

|Architecture & Components (Agent, Manager, Indexer, Dashboard, API)|

|Key Features & Capabilities|

|IDS vs IPS vs EDR — Where Wazuh fits|

|Quick Single-Node Ubuntu Installation (practical commands)|

|Agent deployment examples (Linux & Windows)|

|Integrations — SentinelOne & Suricata (how and why)|

|Active Response (HIPS-like functionality) + sample scripts|

|Scaling & Production Architecture (hardware sizing & clustering)|

|Security & Hardening Checklist|

|SOC Playbooks (ransomware, brute-force, credential theft)|

|Monitoring & Troubleshooting (logs, common errors)|

|Useful commands & config snippets (ossec.conf, rules)|

|Appendix — ports, file locations, references & links|

1 — TL;DR (Executive)
Use Wazuh when you need centralized detection, log correlation, file integrity monitoring, compliance reporting, and automated response for servers, workstations, and cloud workloads. 
Wazuh Documentation

For labs or small teams, a single-node (manager + indexer + dashboard) works well. For production, split components into clusters for HA and scale. 
Wazuh Documentation
+1

2 — Core Concepts & Terminology
SIEM — Centralizes logs, normalizes and correlates events, surfaces prioritized alerts.

HIDS — Host-based IDS: agent-inspected logs/processes/files on each host. Wazuh behaves like an HIDS via its agents. 
Wazuh Documentation

HIPS / Active Response — When detection triggers an automated local or manager-side action (block IP, kill process), Wazuh executes Active Response scripts — this is how Wazuh provides IPS-like behavior. 
Wazuh Documentation

EDR — Endpoint Detection & Response: continuous endpoint telemetry + forensic artifacts. Wazuh provides EDR-style visibility (processes, syscalls, FIM, vulnerability data), though full EDR vendors add deep rollback & patented behavioral engines. 
Wazuh Documentation

Files & Decoders — Wazuh uses decoders to parse raw logs and rules to match suspicious patterns.

Indexer — Search & analytics engine (OpenSearch/Elasticsearch-compatible) used to store and query events. 
Wazuh Documentation

3 — Architecture & Components
Simple flow (single-node):

css
Copy
Edit
[Agent (Endpoint)] -> [Wazuh Manager] -> [Wazuh Indexer (OpenSearch/ES)] -> [Wazuh Dashboard / Kibana]
Primary components

Wazuh Agent — Collects logs, file changes, syscalls, inventory, vulnerability scan results. Cross-platform (Linux, Windows, macOS, Solaris, AIX, containers). 
Wazuh Documentation

Wazuh Manager — Receives agent data, decodes logs, runs rules, triggers alerts and active responses. 
Wazuh Documentation

Wazuh Indexer — Indexes events; supports multi-node clusters for scale. 
Wazuh Documentation

Wazuh Dashboard — UI for alerts, agent management, and reporting. 
Wazuh Documentation

4 — Key Features & Capabilities
Log collection & normalization (syslog, agent logs, application logs). 
Wazuh Documentation

File Integrity Monitoring (FIM) — detect, alert on file changes. 
Wazuh Documentation

Active Response — automated scripts and playbooks to contain threats (e.g., block IPs, stop processes). 
Wazuh Documentation

Vulnerability detection & asset inventory — Syscollector provides software/package inventories to match CVEs. 
Wazuh Documentation

Compliance modules — PCI, HIPAA, GDPR/ISO rule sets and reports. 
Wazuh Documentation

Network IDS ingestion — ingest Suricata/Zeek alerts for correlation with host telemetry. 
Wazuh Documentation

5 — IDS vs IPS vs EDR — Where Wazuh Fits
IDS (Detect) — Wazuh excels as a HIDS: logs, FIM, rules, alerts. 
Wazuh Documentation

IPS (Prevent) — Wazuh is not a dedicated network IPS appliance, but with Active Response it can prevent actions at the host level (firewall rules, process kill). Use Wazuh + Suricata to combine network detection with host prevention. 
Wazuh Documentation
Wazuh

EDR (Detect + Response) — Wazuh provides many EDR capabilities (endpoint telemetry, forensic artifacts, response scripts) but lacks some advanced EDR-only features (e.g., ransomware file-level rollback). Combine Wazuh with an EDR like SentinelOne for full coverage. 
Wazuh

6 — Quick Single-Node Ubuntu Installation (practical)
This is a quickstart intended for lab / PoC. For production, follow multi-node and hardening docs. 
Wazuh Documentation
+1

Tested for Ubuntu Server 24.04 LTS (64-bit). Adjust for different versions.

6.1 Update & prerequisites
bash
Copy
Edit
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl gnupg apt-transport-https unzip lsb-release
6.2 Add Wazuh repository & key
bash
Copy
Edit
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
(Reference: official install guide.) 
Wazuh Documentation

6.3 Install manager, indexer, dashboard
bash
Copy
Edit
sudo apt install -y wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl enable --now wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
6.4 Verify & Quickstart
Access dashboard: https://<WAZUH_HOST>:5601 (follow prompts from the installer/quickstart). 
Wazuh Documentation

7 — Agent Deployment Examples
7.1 Linux agent (Ubuntu example)
bash
Copy
Edit
# On agent host
curl -s https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x.x_amd64.deb -o wazuh-agent.deb
sudo dpkg -i ./wazuh-agent.deb

# Configure manager in /var/ossec/etc/ossec.conf or use agent-auth:
sudo /var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>

sudo systemctl enable --now wazuh-agent
# Verify
sudo systemctl status wazuh-agent
Reference: agent docs. 
Wazuh Documentation

7.2 Windows agent (PowerShell)
Download official MSI from Wazuh docs and use domain-join or agent-auth registration. (See Wazuh docs for the exact MSI link and parameters.) 
Wazuh Documentation

8 — Integrations: SentinelOne & Suricata
8.1 SentinelOne
Two common patterns:

API Pull: Wazuh queries SentinelOne Management API for alerts and ingests them via an integration module or custom Python script.

Webhook Push: SentinelOne pushes events to a webhook endpoint on Wazuh (or an ingestion proxy) for near real-time ingestion.

Wazuh provides example blog walkthroughs showing how to transform SentinelOne events into Wazuh alerts and create mapping rules. Use SentinelOne for deep endpoint blocking + Wazuh for correlation and SIEM analytics. 
Wazuh
Medium

Example: Wazuh blog shows a SentinelOne integration prototype and mapping rules. 
Wazuh

8.2 Suricata (Network IDS)
Why: Suricata detects network-level indicators; Wazuh correlates them with host telemetry for higher-fidelity alerts.

How: Configure Suricata to write EVE JSON logs → forward them to Wazuh manager (file monitoring, Filebeat, or syslog) → create correlation rules. Wazuh has a PoC guide for Suricata integration. 
Wazuh Documentation
Wazuh

9 — Active Response (HIPS-like) — How to use & sample scripts
Active Response lets you run commands when rules trigger. Use-cases: block source IPs, quarantine hosts, notify SOAR.

9.1 ossec.conf active-response snippet
xml
Copy
Edit
<active-response>
  <command>disable-account</command>
  <location>manager</location>
  <rules_id>100001</rules_id>
  <timeout>600</timeout>
  <agents>all</agents>
</active-response>
(See docs for full syntax.) 
Wazuh Documentation

9.2 Sample script: block-ip.sh (manager-side)
bash
Copy
Edit
#!/bin/bash
# block-ip.sh <ip>
IP="$1"
# Add to ufw (idempotent check)
if ! ufw status | grep -q "$IP"; then
  ufw insert 1 deny from $IP to any
fi
Register this script in the Active Response commands directory and map to a rule level. Use stateful responses if you want timed unblocks. 
Wazuh Documentation

10 — Scaling & Production Architecture
Indexer cluster: Use multi-node OpenSearch/Elasticsearch cluster for ingestion capacity, retention, and HA. See indexer sizing guide for RAM & disk recommendations per agents/events. 
Wazuh Documentation

Manager HA: Deploy multiple manager nodes or use load balancer patterns to distribute agents. 
Wazuh Documentation

Storage: Allocate SSDs for indexer nodes and plan retention (GB/day * retention days).

Sizing heuristics (example; validate with your EPS):

Small lab: 4–8 GB RAM, 1–2 CPU for single-node.

Production indexer nodes: 32–64 GB RAM, fast NVMe, multiple cores. Refer to official indexer hardware guidance. 
Wazuh Documentation

11 — Security & Hardening Checklist
Enable TLS for Wazuh API & Dashboard; rotate certificates regularly. 
Wazuh Documentation

Restrict management plane network (agents communicate to manager over controlled ports).

Enforce strong admin credentials and SSO for Dashboard (OIDC/SAML if supported). 
Wazuh Documentation

Harden OS (CIS benchmarks), minimize exposed services.

Use token-based registration and rotate API tokens; audit tokens.

Backup indexer snapshots frequently.

12 — SOC Playbooks (Concise)
12.1 Ransomware detection & response
FIM detects mass modifications → trigger HIGH alert.

Correlate with endpoint process creation & EDR event (SentinelOne) → confirm. 
Wazuh

Active Response: isolate host (block gateway, disable network adapter), kill offending process, collect memory & disk artifacts.

Notify IR team (PagerDuty/Slack), create case in SOAR/TheHive.

12.2 Brute-force login
Detect many failed auth attempts → rule triggers.

Active Response: block source IP (iptables/ufw) for 1 hour.

Create ticket and hunt for lateral movement indicators.

13 — Monitoring & Troubleshooting
Manager logs: /var/ossec/logs/ossec.log and journalctl -u wazuh-manager -f.

Agent status: sudo /var/ossec/bin/agent_control -l (list agents). 
Wazuh Documentation

Indexer health: check OpenSearch/ES cluster health APIs and disk usage.

Common issue: agents not connecting — check time sync (NTP), firewalls, manager IP in agent config.

14 — Useful Commands & Config Snippets
Agent list (manager)
bash
Copy
Edit
/var/ossec/bin/agent_control -l
API: list agents (example)
bash
Copy
Edit
# Acquire API token via login endpoint then:
curl -k -X GET "https://<WAZUH_HOST>:55000/agents" -H "Authorization: Bearer $TOKEN"
Example Wazuh rule (detect SSH brute force)
xml
Copy
Edit
<rule id="100100" level="10">
  <if_sid>5710</if_sid>
  <description>Multiple failed SSH authentication attempts - potential brute force</description>
  <group>authentication_failed,</group>
  <mitre>
    <id>T1110</id>
  </mitre>
  <options>no_full_log</options>
</rule>
15 — Appendix
Ports (common)
Manager API: 55000 (HTTPS)

Dashboard (Kibana): 5601 (or configured)

Agent-manager: default over TCP (1514/1515 depending on TLS) — confirm in your ossec.conf and docs.

File locations
Manager logs: /var/ossec/logs/ossec.log

Agent config: /var/ossec/etc/ossec.conf

Active Response scripts: /var/ossec/active-response/bin/ (or configured path)

References & Further Reading
Wazuh Quickstart & Agent docs. 
Wazuh Documentation
+1

Wazuh Architecture & Components. 
Wazuh Documentation
+1

Installing the Wazuh server: step-by-step guide. 
Wazuh Documentation

Wazuh Active Response docs. 
Wazuh Documentation
+1

Integrating SentinelOne XDR with Wazuh (Wazuh blog). 
Wazuh

Network IDS integration (Suricata) PoC. 
Wazuh Documentation
Wazuh

Wazuh Indexer installation & sizing. 
Wazuh Documentation
