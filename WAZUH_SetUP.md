# **Setting up Wazuh**

## **Objective**  
The objective of this task is to help you **set up a Wazuh Server using the Quick Start method** and **onboard an Ubuntu machine as an agent**. By completing this task, you will learn how to deploy **Wazuh for security monitoring, log analysis, and threat detection**.  
Wazuh is an ***open-source threat detection, integrity monitoring, and security analytics platform*** that centralizes endpoint telemetry and security events so security teams can detect, investigate, and automate response workflows.  
This repo contains: conceptual overview, IDS/IPS + use-cases, and a step-by-step Ubuntu setup playbook for a single-node lab/prod starter deployment.

---
## **What is Wazuh**  
Wazuh is an agent-based security platform (HIDS/HIPS + SIEM/XDR capabilities) where lightweight agents forward telemetry to a central manager and indexer for real-time analysis, alerting, and centralized investigation. The architecture centers on agents, a manager, an indexer, and a dashboard/API.

---

## **Why Wazuh?**  
- Centralize endpoint & infrastructure telemetry to reduce MTTR and increase detection fidelity.

- Automate response workflows via integrator module / API, enabling acceleration of SOC runbooks.

- Meet compliance and configuration-audit requirements (CIS, PCI, HIPAA) with file integrity monitoring (FIM) and configuration assessment. 

---

## **IDS / IPS Use Cases** (where Wazuh fits)
- Host-based IDS (HIDS): File Integrity Monitoring, rootkit detection, suspicious process/activity detection.

- Host-based IPS / Active Response: Trigger automated containment actions (block IP, stop process, quarantine files) via Wazuh active-response and integrator workflows.

- Network IDS integration: Wazuh can ingest alerts from NIDS (e.g., Suricata) to correlate network events with endpoint telemetry for richer detector context. 
documentation.wazuh.com

- Endpoint + EDR correlation: Combine EDR events (SentinelOne, CrowdStrike, etc.) with Wazuh logs for single-pane triage and threat hunting. (See SentinelOne integration notes below.) 

---

1. IDS — Intrusion Detection System
Purpose: Detect malicious activity, policy violations, or suspicious behavior.

How it works in Wazuh:

Collects logs, file integrity events, syscalls, network IDS alerts (if integrated), and correlates them against rules.

Alerts the SOC team when suspicious activity is detected.

Does not automatically block the activity — detection only.

Example in Wazuh:

Detecting multiple failed SSH login attempts from the same IP.

Spotting a known malicious hash during a file scan.

2. IPS — Intrusion Prevention System
Purpose: Detect and automatically stop or mitigate malicious activity in real time.

How it works in Wazuh:

Uses Active Response — scripts or commands triggered by rules.

Can block IPs using firewall rules, kill malicious processes, disable accounts, or integrate with firewalls/EDRs for isolation.

Example in Wazuh:

Detecting a brute force SSH attack and adding the attacker’s IP to iptables/firewalld to block further attempts.

Detecting ransomware activity and instantly isolating the endpoint.

3. Wazuh as IDS/HIDS & HIPS
Wazuh is a Host-based IDS (HIDS) because it works at the endpoint/host level, not just on the network.

When you enable Active Response, it also acts as a Host-based IPS (HIPS).

You can extend this by feeding Network IDS (NIDS) logs (like Suricata or Zeek) into Wazuh so it can correlate network-level detections with host-level detections.


## 🧠 **Introduction to EDR (Endpoint Detection and Response)**

**EDR** refers to tools that monitor, record, and analyze activities on endpoints (servers, desktops, laptops) to detect malicious behavior, help in incident response, and enable threat hunting.

---

## 🔎 **How Does a SOC Analyst Use EDR?**

SOC Analysts rely on EDR tools to:
- Detect suspicious behaviors (e.g., process injection, lateral movement)
- Investigate alerts and correlate activity over time
- Isolate or respond to infected endpoints
- Pull forensic artifacts like logs, memory dumps, and timelines
- Hunt for threat indicators (IOCs)

---

## 🏆 **Popular EDR Platforms**

| Platform           | Description                                              |
|--------------------|----------------------------------------------------------|
| **Wazuh**           | Open-source SIEM + EDR, host-based log monitoring, FIM   |
| **Microsoft Defender for Endpoint** | Native EDR for Windows with behavioral analytics   |
| **CrowdStrike Falcon**   | Cloud-based EDR with threat hunting capabilities     |
| **SentinelOne**     | Autonomous endpoint protection and rollback features     |
| **Elastic Endpoint (with ELK)** | Lightweight endpoint monitoring integrated into Elastic SIEM |

---

## **Lab Task: Setting up Wazuh EDR**  

### **Requirements**  
- **System 1:** Ubuntu 22.04/20.04 (Wazuh Server)  
- **System 2:** Ubuntu 22.04/20.04 (Agent Machine to be monitored)  
- **Minimum Hardware for Wazuh Server:**  
  - **CPU:** 4 vCPUs  
  - **RAM:** 8GB+  
  - **Storage:** 50GB+  
- **Network Connectivity:** Ensure both systems can communicate over the network.  
- **User Permissions:** Root or sudo privileges on both machines.  

---

### **Step 1: Install Wazuh Server Using Quick Start**
1. Download and run the Wazuh installation assistant.
```
curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```
Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful.

```
INFO: --- Summary ---
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
    User: admin
    Password: <ADMIN_PASSWORD>
INFO: Installation finished.
```
- You now have installed and configured Wazuh.

2. Access the Wazuh web interface with https://<WAZUH_DASHBOARD_IP_ADDRESS> and your credentials:

- Username: admin
- Password: <ADMIN_PASSWORD>

### Step 2: Onboard an Ubuntu Machine as a Wazuh Agent
1. Install the Wazuh Agent on the Ubuntu machine to be monitored:

```
curl -sO https://packages.wazuh.com/4.7/wazuh-agent-linux.sh && sudo bash wazuh-agent-linux.sh
```
2. Configure the Wazuh Agent to connect to the Wazuh Server:

```
sudo nano /var/ossec/etc/ossec.conf
```
Locate <address> and set it to the Wazuh Server IP:
```
<address>WAZUH-SERVER-IP</address>
```
3. Start the Wazuh Agent service:

```
sudo systemctl start wazuh-agent
```
4. Enable the agent to start at boot:

```
sudo systemctl enable wazuh-agent
```

### Step 3: Verify Agent Connection in Wazuh Dashboard
1. Open Wazuh Dashboard (http://<Wazuh-Server-IP>:5601).
2. Navigate to "Agents" in the Wazuh UI.
3. Check if the Ubuntu agent is listed as "Active".

✅ Learned how SOC analysts use Wazuh for security monitoring and log analysis.    

