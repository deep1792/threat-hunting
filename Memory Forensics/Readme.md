Memory Forensics - End to End Threat Analysis for threat hunters

Youtube Link -- https://youtu.be/ywXExskz2CA?si=Exuty5bHF9lkgeTJ

 🧠 What is Memory?

Memory (RAM) is a volatile storage medium that temporarily holds data and programs being used by the CPU.
When a program runs:

 CPU interprets instructions.
 Data and code are loaded from storage (HDD/SSD) into RAM using bootloaders, GRUB (Grand Unified Boot Loader) 
 RAM provides fast access, enabling efficient execution.

---

 🧩 Types of Memory

| Type           | Description                                                    |
| -------------- | -------------------------------------------------------------- |
| Cache      	 | Fastest, small memory in CPU for temporary data.               |
| RAM (DDR4)	 | Main volatile memory, holds OS, applications, and active data. |
| DRAM	         | Dynamic RAM, requires refresh cycles.                          |
| SRAM	         | Static RAM, faster and costlier, used in CPU cache.            |
| Rambus RAM 	 | High-speed memory, legacy tech.                                |
| ROM       	 | Non-volatile, stores firmware.                                 |
| PROM/EPROM	 | Programmable and Erasable PROMs used for firmware and BIOS.    |


---

 🧬 Order of Volatility

| Volatility Rank | Data Type                          |
| --------------- | ---------------------------------- |
| 1               | CPU Cache, Registers               |
| 2               | Memory (RAM), Kernel Stats         |
| 3               | Process Table, Network Connections |
| 4               | Disk (Files, Logs)                 |
| 5               | Remote Logs                        |
| 6               | Configuration Files                |
| 7               | Backups / Archives                 |

1 --> 2 --> 3 --> 4 --> 5 --> 6 --> 7

---

 ⚡ Why Memory Forensics?

 Identify Stealthy Attacks (e.g. fileless malware, code injections)  -- playlists ---->> malware 
 Root-Cause Investigation of incidents.
 Live IOC Extraction (indicators in RAM like commands, strings).
 Legal Compliance in evidence gathering.
 Detect Threats Unseen on Disk (malware may live only in memory).

---

 📥 Memory Acquisition Process

| Stage                    | Notes                                          |
| ------------------------ | ---------------------------------------------- |
| Local vs Remote          | Decide based on access scope.                  |
| Physical Acquisition 	   | Full RAM dump (e.g., ".raw", ".bin").          |
| Process Memory           | Target specific malicious processes.           |
| Live Commands            | Extract memory-resident data using live tools. |

---

 🚧 Challenges in Memory Acquisition

 Deadlocks or hangs.
 Page faults (accessing non-resident memory).
 RAM Encryption (esp. in modern systems).
 Cache data extraction.
 IoT device constraints.
 Ensuring data integrity with hash verification.

 🔄 Reboot Sustainability

 - RAM is volatile, so data is lost on shutdown.
 - Artefacts (like malware code, keys, credentials) often reside in memory.
 - Always acquire memory before reboot.
 - If already rebooted, tools like Afterlife attempt to recover lost data (limited success).

---

 🛠️ Tools for Acquisition & Analysis

 📦 Acquisition Tools (Must-Demo)

| Tool                     | Description                       |
| ------------------------ | --------------------------------- |
| Magnet RAM Capture       | Lightweight, reliable.            |
| DumpIt (Moonsols)        | Popular one-click dump.           |
| Rekall winpmem           | CLI-based, scriptable.            |
| Bekasoft RAM Capture     | GUI-based simple tool.            |
| FTK Imager               | Supports RAM dump + imaging disk. |

 🔍 Memory Analysis Tools (Full Demos)

| Tool            | Feature Highlights                               |
| --------------- | ------------------------------------------------ |
| Volatility2     | Legacy, widely used, Python2.                    |
| Volatility3     | Modern, modular, Python3.                        |
| MemProcFS       | Treats memory dumps like a file system.          |
| Orochi          | GUI version of Volatility for easier navigation. |

---

 🧠 Memory Management Concepts

| Concept                     | Malware Implication                                             |
| --------------------------- | --------------------------------------------------------------- |
| Static/Dynamic Loading      | Malware may hide in dynamically loaded modules.                 |
| Linking                     | Dynamic linking abused for DLL injection.                       |
| Virtual Memory & Paging     | Malware can manipulate page tables.                             |
| Address Translation         | Important in translating virtual to physical offsets.           |
| Swapping                    | Part of RAM moved to disk; affects memory capture completeness. |

-----------------------------------------

 🧪 Memory Leak Detection 

 🔍 What is a Memory Leak?

A memory leak occurs when a program:

 Allocates memory (e.g., via "malloc", "new", etc.),
 But never releases it back to the system, even when it's no longer needed.

Over time:

 The RAM usage increases, possibly to exhaustion.
 System performance degrades.
 It may even crash or freeze.
 In malware analysis, leaky malware or injected processes can cause these symptoms, either intentionally (to DoS a system) or due to poor coding.

---

 🚨 Symptoms of Memory Leaks

 Gradual increase in memory usage (RAM usage keeps climbing).
 System slowdown or high memory pressure.
 Unusual memory patterns in certain processes.
 Tools like Task Manager showing ever-increasing memory for a single process.
 In a forensic case, stealthy persistence mechanisms or process hollowing may exhibit memory leaks.
---

 🛠️ Tool: Debug Diagnostic Tool (DebugDiag)

 📌 What It Is:

 A Microsoft-provided GUI tool for troubleshooting performance issues.
 Designed to analyze process dumps and detect:

   Memory leaks
   Handle leaks
   Crashes
   Hangs

---

 🧰 How It Works:

1. Download and Install Debug Diagnostic Tool

    [https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-diagnostic-tool-overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-diagnostic-tool-overview)

2. Set up a Rule:

    Choose "Memory and Handle Leak".
    Select the target process (e.g., "chrome.exe", suspicious process, etc.).
    Attach debugger or start monitoring.

3. Monitor the Process:

    It will monitor heap allocations over time.
    Generates a report with graphs showing memory usage.
    Shows which functions/modules are responsible for memory allocations.

4. Analyze the Report:

    Reports in ".mht" format (open with a browser).
    Look for:

      Steady growth in memory
      Leaked modules or functions
      Suspicious DLLs or threads

---

 📉 Reading the Graphs

 📈 Stair-step upward or straight upward slope → Memory leak is likely.
 ↔️ Horizontal (flat) usage or fluctuation → Healthy memory management.
 📉 A dip (release of memory) → GC or memory freed properly.

---

 🧠 Forensic Use-Cases:

 Malware Behavior Profiling: If a malware sample causes memory leaks, it can be a unique behavioral indicator.
 Injected DLL Detection: If memory leaks start after a DLL injection, the DLL may be malicious.
 Attribution of Leak: Maps leaks to the function/module responsible, useful in reverse engineering malware.

---

 🔐 Security Twist:

 Leak as a Side Channel: In some cases, attackers intentionally leak memory to:

   Create performance issues
   Distract defenders
   Store temporary payloads in memory

---

So, to demonstrate i have written a simple python code that will perform the memory leak 
---
code --
import time

print("Starting aggressive memory leak demo...")

leak_list = []  # Store allocated memory chunks

try:
    while True:
        # Allocate 100MB of binary data per iteration
        chunk = b'A' * (100 * 1024 * 1024)  # 100 MB binary block
        leak_list.append(chunk)            # Intentional memory leak

        print(f"Leaked another 100MB... Total memory leaked: {len(leak_list) * 100} MB")
        time.sleep(1)  # Slight delay to make the spike noticeable but controlled

except KeyboardInterrupt:
    print("\nMemory leak demo interrupted by user.")
	
	
Now observe the patterns using the TaskManager and Performance Monitor	
	
   Line going up in stairs = leak.
   Irregular but declining = normal memory release.

---------------------------------------------------------------------------------------------------

 🧭 Malware Analysis Roadmap (Infection/Malware In Memory)

1. Initial Triage

    Acquire memory before reboot.
    Collect hashes, filenames, memory usage stats.

2. Environment Setup

    Install Volatility 3, obtain correct symbols.
    Set up plugins and custom detection modules.

3. Run Baseline Plugins

    "windows.pslist" / "psscan" – identify processes.
    "cmdline", "consoles" – look for suspicious commands.
    "dlllist", "handles" – check DLL injection.
    "malfind" – scan for code injections.
    "ldrmodules" – detect stealthy or unmapped modules.

4. Advanced Techniques

    Extract memory regions for reverse engineering.
    Detect:

      Reflective DLL injections
      Process hollowing
      Ransomware key material
      Credential dumping artifacts (LSASS memory)

5. IOC Generation

    Pull IPs, domains, hashes, filenames, mutexes.
    YARA scan on memory regions.

6. Report & Remediate

    Document findings with timeline.
    Link malware behavior with threat actor TTPs.
    Provide mitigation & IR recommendations.

---

- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.info
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.pslist
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.psscan
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.cmdline
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.dlllist --pid 7896 
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.netscan
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.handles --pid 7896 
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.filescan
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.filescan > complete-file-scan.txt
- sudo grep -i "medusa" complete-file-scan.txt
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.malfind
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.malfind > complete-malfind-scan.txt
- sudo grep -i "medusa" complete-malfind-scan.txt
- sudo grep -i "med" complete-malfind-scan.txt
- sudo grep -i ".tmp" complete-malfind-scan.txt
sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.threads | grep "cmd"
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.registry.hivescan 
sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.registry.hivelist
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.registry.printkey --key "ControlSet001\Services"
- sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.registry.printkey | grep "medusa"
sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.callbacks

Custom Yara Detection
sudo python3 vol.py -f /home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw windows.vadyarascan --yara-file custom-yara-detection.yar 

USER\S-1-5-21-1018563380-2844192730-779781346-1001\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION


Run the ./medusa_triage.sh
