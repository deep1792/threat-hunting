 🎯 Cyber Threat Intelligence (CTI) – Deep Dive

> CTI is the analyzed information about an adversary’s intent, capabilities, and opportunity to compromise a target. It’s produced from various data points and serves decision-makers.

 🔍 Analyze the Adversary:

 Who is attacking (e.g., APT28, FIN7)
 Why (espionage, financial gain)
 How (phishing, zero-days)
 Where from (infrastructure, domains)
 When (timeline of operations)

---

 🧩 From the Perspective of the Client (Consumer-Oriented CTI):

| Client Type	  | Intelligence Need                          		| CTI Example                                                 	   |
| --------------- | ----------------------------------------------- | ---------------------------------------------------------------- |
| SOC Analyst     | IOC feed + detection rules                      | Hashes, domains, Sigma rules for current malware campaigns       |
| Threat Hunter   | Adversary TTPs and historical campaign analysis | MITRE mappings for APT10; hunting queries for beaconing traffic  |
| Executive/CISO  | Strategic threat landscape overview             | High-level threat report on ransomware trends and risks for Q3   |
| IR Team         | Attribution, malware reverse engineering        | Malware family identification, attack vector analysis            |
| Government/LE   | Actor attribution, geopolitical implications    | CTI on nation-state campaigns (e.g., SolarWinds, Moonlight Maze) |
                                                         
---

 🔐 1. Cyberspace: The Operating Terrain of CTI

Cyberspace is the domain in which all cyber threat activities take place. It is composed of multiple interlinked layers:

 ▪️ Physical Layer:

Definition: Tangible components of networks and infrastructure.

Examples:

 Routers, switches, servers, network cables, data centers
 An attacker physically tampers with a router or uses RF attacks on wireless routers (like WiFi Pineapple).

 ▪️ Logical Layer:

Definition: Non-physical elements such as applications and protocols.

Examples:

 Operating systems, browsers, cloud services, communication protocols.
 Exploiting Apache Log4j vulnerability in a cloud-based application represents a threat at this layer.

 ▪️ Information Layer:

Definition: Actual data – what the attacker targets or manipulates.

Examples:

 Emails, chat messages, documents, databases.
 Phishing emails that trick users into entering credentials or open weaponized documents (macro-laden Word files).

---

 💣 2. Threat: The Actor and Their Intent

 A threat is defined as intention + capability + opportunity

 🧠 Intention (Why):

Definition: The motive or objective of the adversary.

Examples:

 Cybercriminals want money → deploy ransomware (e.g., LockBit)
 Nation-states seek espionage → target diplomatic emails
 Hacktivists want to disrupt → deface websites

---

 🛠️ Capabilities (How):

Definition: Tools, tactics, techniques, and procedures (TTPs) used.

Examples:

 Malware (e.g., Cobalt Strike, Mimikatz)
 Exploits (e.g., CVE-2021-44228 – Log4Shell)
 TTPs mapped to MITRE ATT\&CK (e.g., T1059 – Command Scripting)

---

 🕳️ Opportunity (Where & When):

Definition: Weakness or entry point that allows the threat to exploit.

Examples:

 Misconfigured firewalls
 Unpatched vulnerabilities
 Users falling for phishing campaigns

---

 📡 3. Intelligence: From Data to Decision

> Intelligence is processed, validated, analyzed, and actionable information. CTI exists to serve decisions.

 🎯 Primary Goal:

Facilitate the decision-making process for defenders, CISOs, SOC teams, executives, or law enforcement.

---

CTI Lifecycle (with Examples)

 1. Planning and Direction

Definition: Define the questions CTI must answer.

Examples:

 “Which APT groups are targeting the financial sector?”
 “What are the TTPs of Medusa ransomware?”

---

 2. Collection

Definition: Gather raw data from various sources.

Examples:

 OSINT: Pastebin dumps, Twitter IOCs
 Internal logs: SIEM, firewall, EDR
 Dark web scraping

---

 3. Processing

Definition: Structure and format data for analysis.

Examples:

 Parsing IOC feeds (convert into STIX or JSON)
 Deobfuscating malware strings

---

 4. Analysis and Production

Definition: Turn processed data into actionable intel.

Examples:

 “APT29 uses spear-phishing to drop WellMess malware in government orgs”
 Map adversary's infrastructure using passive DNS

---

 5. Dissemination

Definition: Deliver the intel to the right consumer in a useful format.

Examples:

 Threat reports (PDF, STIX)
 Dashboards (OpenCTI, MISP)
 Alerts to SOC analysts via SIEM

-----------------------------------------------------------

 🧠 Cyber Threat Intelligence: Key Terminologies Explained

 🎭 1. Threat Actor

Definition: A person, group, or nation-state responsible for malicious cyber operations.

Types of Threat Actors:

| Type           | Description                                                   | Example                       |
| -------------- | ------------------------------------------------------------- | ----------------------------- |
| Cybercriminals | Financially motivated; engage in ransomware, fraud, etc.      | LockBit, Conti                |
| APT Groups     | Nation-state or state-sponsored; focus on espionage, sabotage | APT28 (Russia), APT10 (China) |
| Hacktivists    | Ideologically motivated; deface, leak, or disrupt for a cause | Anonymous, LulzSec            |
| Script Kiddies | Amateur attackers using pre-made tools without deep knowledge | Defacing school websites      |

---

 🧑‍💻 2. Persona

Definition: The online identity or alias used by a threat actor to remain anonymous.

Context:

 Used in dark web forums, Telegram, or initial access markets.
 Helps CTI teams track behaviors and link aliases across platforms.

Example:

 A ransomware operator uses the persona "ShadowSpider" on multiple RaaS forums.

---

 📋 3. Intelligence Requirements (IRs)

Definition: Questions or needs that guide the collection and analysis of threat intelligence.

Purpose: To ensure intelligence is client-driven, targeted, and relevant.

Examples:

 What TTPs are associated with the latest LockBit 3.0 campaign?
 Have any Russian APTs been observed targeting Latvia in the past 6 months?

📌 Best Practice: Define IRs during the Planning & Direction phase of the intelligence cycle.

---

 🎯 4. Campaign

Definition: A coordinated series of malicious activities aimed at a long-term objective.

Key Traits:

 Multiple operations (phishing, malware deployment, C2 communication).
 May span weeks to years.

Example:

 APT33 launching multiple spear-phishing attacks targeting Middle Eastern oil companies over 18 months — part of a larger campaign for economic espionage.

---

 ⚔️ 5. TTPs – Tactics, Techniques, and Procedures

| Term          | Description                                         | Example                                                                                      |
| ------------- | --------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| Tactic    	| The high-level objective or phase of the attack	  | Initial Access, Execution, Persistence (MITRE ATT\&CK Tactics)                               |
| Technique 	| The method used to achieve the tactic          	  | Spear-phishing (T1566), Credential Dumping (T1003)                                           |
| Procedure 	| The specific implementation of the technique  	  | Sending a malicious PDF via email spoofed from [HR@targetcorp.com](mailto:HR@targetcorp.com) |

🔍 Use: TTP analysis helps in actor profiling, defense hardening, and hunting queries.

---

 🚨 6. Intrusion

Definition: Any attempt by an adversary to compromise a system, whether successful or not.

Importance:

 Even failed intrusions provide valuable IOCs, TTP patterns, and threat insights.
 Should be logged, correlated, and analyzed for trend detection.

Example:

 Multiple failed brute-force attempts on an SSH service → could indicate a larger scan-and-exploit operation.

---

 🟢 🔴 7. Traffic Light Protocol (TLP)

Definition: A color-coded system for managing information sharing boundaries within and across organizations.

| TLP Color        | Information Sharing Boundaries                     	 | When to Use                                        		| How to Share                        	   |
| -----------------| --------------------------------------------------------| ---------------------------------------------------		| -----------------------------------------|
| TLP\:RED         | Restricted to specific individuals or groups            | Sensitive info impacting privacy, safety, or operations 	| DO NOT share outside original recipients |
| TLP\:AMBER       | Limited disclosure within recipient’s organization only | May impact operations if shared widely                 	| Internal use only                        |
| TLP\:AMBER+STRICT| Only with specified partners                            | Custom sharing restriction to subset partners           	| By agreement only                        |
| TLP\:GREEN       | Share with peer organizations in the community          | Valuable for community defense                          	| Peer and trusted partner sharing allowed |
| TLP\:WHITE       | Publicly shareable                                      | No risk in disclosure                                   	| May publish or post                      |


🔗 [More info on TLP](https://www.first.org/tlp/)

---

 🧬 8. IOC – Indicator of Compromise

Definition: A technical artifact linked to malicious activity, especially useful for detection and hunting.

| IOC Type  	  | Examples                                 	     |
| --------------- | ------------------------------------------------ |
| Hashes          | `d41d8cd98f00b204e9800998ecf8427e` (MD5), SHA256 |
| IP Addresses    | `45.129.200.31` (C2 IP)                          |
| URLs/Domains    | `malicious-site[.]ru`, `update-google[.]com`     |
| File Names      | `invoice.docm`, `payload.exe`                    |
| Email Addresses | `hr-dept@targetcorp.com`                         |
| Registry Keys   | `HKCU\Software\BadMalware\Persistence`           |

⚙️ Best Use:

 Feed into SIEM, EDR, firewall, or YARA/Sigma detection systems.

--------------------------------------------------------

 🔍 CTI-Specific Models: Detailed Explanation + Real-World Examples

 🎯 Purpose of These Models

 Represent adversary behaviors and attack flows
 Support IOC prioritization and incident response
 Standardize intelligence dissemination
 Track evolution of TTPs and threat groups

---

 🧱 1. Cyber Kill Chain (CKC)

📘 Developed by: Lockheed Martin
🎯 Purpose: Map the stages of a cyber intrusion to detect and disrupt at each stage
📈 Goal for defenders: Stop the intrusion as early as possible (before “Actions on Objectives”)

 🔁 Stages:

| Stage                      | Description                                   | Example                              |
| -------------------------- | --------------------------------------------- | ------------------------------------ |
| Reconnaissance       	     | Adversary collects data about the target      | Scanning for open ports              |
| Weaponization          	 | Malware or exploit package creation           | Creating a malicious PDF exploit     |
| Delivery               	 | Transmission to victim                        | Spear-phishing email with payload    |
| Exploitation           	 | Triggering the vulnerability                  | User opens malicious attachment      |
| Installation           	 | Malware installs a backdoor                   | Dropper installs remote access tool  |
| Command & Control (C2) 	 | Attacker establishes remote control           | Malware connects to C2 server        |
| Actions on Objectives  	 | Executes final goal (data theft, destruction) | Data exfiltration to attacker server |

 📄 Real-Life Example: Emotet Intrusion

 Recon: Collected target org emails (e.g., through prior phishing)
 Weaponization: Packed macro-enabled Word doc
 Delivery: Spear-phishing with invoice-themed email
 Exploit: User enables macros
 Install: Emotet downloader installs TrickBot
 C2: Beacons to hardcoded C2 IP
 Action: Data theft, ransomware deployment (Ryuk)

---

 💎 2. Diamond Model of Intrusion Analysis

📘 Developed by: Caltagirone, Pendergast & Betz (2007)
🎯 Purpose: Analyze relationships between adversary, capability, infrastructure, and victim

 🧩 Core Elements:

 Adversary – Threat actor or group (e.g., APT28)
 Infrastructure – C2 domains, compromised servers (e.g., `mail-login[.]ru`)
 Victim – Targeted entity (e.g., Government of Ukraine)
 Capabilities – Malware, exploits (e.g., X-Agent, spear phishing)

 📄 Real-Life Example: APT28 Attack

 Adversary: APT28 (Fancy Bear)
 Infrastructure: Domains like `update[.]office365portal[.]ru`
 Victim: NATO defense contractors
 Capability: Spear-phishing with macro-laced DOCX, X-Agent malware

📌 Use in CTI:

 Helps in attribution, tracking campaigns, and pivoting (e.g., reuse of infrastructure across victims)

---

 🧠 3. MITRE ATT\&CK Matrix

📘 Maintained by: MITRE Corporation
🎯 Purpose: Taxonomy of real-world adversary behaviors and TTPs
🌐 Public Resource: [https://attack.mitre.org/](https://attack.mitre.org/)

 🧬 Structure:

 Tactics: Why (objective)
 Techniques: How (method)
 Sub-techniques: Specific implementations

 🔢 Sample ATT\&CK Chain (Tactic → Technique → Sub-technique):

| Tactic              | Technique                  | Sub-technique                        |
| ------------------- | -------------------------- | ------------------------------------ |
| Initial Access  	  | Phishing (T1566)           | Spearphishing Attachment (T1566.001) |
| Execution       	  | Command and Scripting      | PowerShell (T1059.001)               |
| Persistence     	  | Registry Run Keys (T1547)  | —                                    |
| Defense Evasion 	  | Obfuscated Files (T1027)   | —                                    |
| C2              	  | Application Layer Protocol | HTTPS (T1071.001)                    |

🔍 Use in CTI:

 Track adversary trends (e.g., “APT29 heavily uses T1059.001”)
 Map threat reports or SIEM alerts to known techniques
 Help defenders write Sigma/YARA rules aligned with known TTPs

✅ Toolkits:

 MITRE ATT\&CK Navigator
 Threat Mapping in MISP / OpenCTI

---

 🧱 4. Pyramid of Pain

📘 Created by: David Bianco
🎯 Purpose: Demonstrates the difficulty (and impact) of detecting different indicators

 🔺 Structure (from bottom to top):

| Level              | Description                           | Pain for Adversary 
| ------------------ | ------------------------------------- | ------------------ 
| Hash Values   	 | Specific file fingerprints            | 🟢 Low             |
| IP Addresses  	 | C2, exfil points                      | 🟢 Low             |
| Domain Names  	 | Short-lived, disposable               | 🟡 Moderate        |
| Host Artifacts	 | Registry keys, file paths             | 🟡 Moderate        |
| Tools         	 | Malware families, frameworks (Cobalt) | 🔴 High            |
| TTPs          	 | Behavioral patterns                   | 🔴🔴 Very High    |

🔍 Use Case:

 Focus on detecting TTPs (e.g., lateral movement via `wmic`) rather than just static IPs
 YARA rules and behavioral analytics help hit the top of the pyramid
 Better long-term defense

---

 🎓 Summary Table – CTI Models Comparison

| Model                | Focus                                                     | Best For                                    |
| -------------------- | --------------------------------------------------------- | ------------------------------------------- |
| Cyber Kill Chain	   | Stages of an intrusion                                    | Incident response, detection strategy       |
| Diamond Model    	   | Relation between actor/infrastructure/capabilities/victim | Attribution, campaign tracking              |
| MITRE ATT\&CK    	   | Adversary TTPs in matrix format                           | Threat hunting, red teaming, blue teaming   |
| Pyramid of Pain  	   | Detection value of indicators                             | Prioritizing IOC hunting, proactive defense |


----------------------------------------------------------

Analysis on APT-36 from pdf

----------------------------------------------------------

Designing the in-house analysis report for Primo analysis

