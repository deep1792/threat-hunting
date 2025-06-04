# pe32ransomware complete details

Youtube Link - https://www.youtube.com/@deepanshukhannahacker 
Linkedin Profile - https://www.linkedin.com/in/deepanshukhanna/


- PE32 Ransomware is a new, messy, and amateur-level ransomware that connects over telegram channel using bot as back-connection and communication encrypts your files and asks for money (ransom) to unlock them.
- It is sloppy, noisy, and very easy to detect, but it still works and can cause real damage.
- It talks (communicates) to the attacker using Telegram — instead of using secret servers or hidden networks.

---

 How PE32 Ransomware Works (Execution Flow)

 Step 1: Infection
- You open/run a malicious file (PE32.exe).
- The malware asks (or auto-decides) if it should encrypt:
  - Just the folder it’s in
  - Or the whole computer.

---

 Step 2: Fast and Loud Encryption
- Immediately starts encrypting the most visible folders:
  - Desktop, Documents, Downloads.
- Adds ".pe32" extension to every encrypted file.
  - Example: "photo.jpg" → "photo.jpg.pe32"

---
 Step 3: Creates Special Folder
- Creates a folder at "C:\PE32-KEY\".
- Inside, it saves important files:
  - "README.txt" → The ransom note.
  - "ID" → Your computer’s unique ID.
  - "context.pe32c", "lock.pe32", "pe32lockfile.lock" → Tracking files to know what it has done.

---
 Step 4: Communication Over Telegram
- Sends messages to a Telegram group chat the attacker controls.
- Messages include:
  - Your computer’s ID
  - Status updates (e.g., "UltraFast encryption completed")
- Mistake: The attacker left their Bot Token visible — making it easy for researchers to spy or break in.

Important Details About PE32 Behavior

| Aspect             | Description 
|--------------------|-------------
| Encryption     	 | Uses ChaCha20 (strong, fast encryption). -- most likely
| Communication  	 | Only through Telegram Bot API. No hidden servers. 
| Coding Quality 	 | Very messy, full of spelling mistakes ("extentions" instead of "extensions"). 	
| Detection      	 | Very easy — it triggers disk repair, encrypts system files randomly.
| Stealth       	 | None — no hiding, no special evasion tricks. 
| Libraries Used	 | Windows standard libraries: "kernel32.dll", "ntdll.dll", "bcrypt.dll", "crypt32.dll". 
| Indicators 	     | Creates ".lock" && "pe32" files, ransom notes, and broken system files.
| Exposed Secrets	 | Leaks the Telegram Bot Token publicly inside its code. 

---

Pe32-ransomware analysis -- 

sudo strings pe32ransomware.exe >> strings.txt
sudo floss pe32ransomware.exe
sudo capa pe32ransomware.exe

sudo dshell
decode -h
decode -l
decode -p dns pe32ransomware.pcap | sort
decode -p netflow pe32ransomware.pcap | sort
decode -d reverseflows pe32ransomware.pcap
decode -d toptalkers pe32ransomware.pcap
decode -d largeflows pe32ransomware.pcap
decode -p httpdump pe32ransomware.pcap
decode -p followstream pe32ransomware.pcap
decode -p tftp pe32ransomware.pcap
decode -p ftp pe32ransomware.pcap
decode -d web pe32ransomware.pcap

sudo qu1cksc0pe --file pe32ransomware.exe --vtFile
sudo qu1cksc0pe --file pe32ransomware.exe --packer
sudo qu1cksc0pe --file pe32ransomware.exe --domain
sudo qu1cksc0pe --file pe32ransomware.exe --sigcheck
sudo qu1cksc0pe --file pe32ransomware.exe --mitre
sudo qu1cksc0pe --file pe32ransomware.exe --analyze --report
sudo qu1cksc0pe --file pe32ransomware.exe --watch


 1. Basic Information

Target OS: Windows\
File Type: Portable Executable (PE32) - Windows 32-bit Executable

Definitions:

- PE32: Standard executable file format for 32-bit Windows applications.
- Target OS: Specifies the intended operating system environment.

Observation:

- The file is designed exclusively for the Windows platform.

---

 2. Import and Export Analysis

The ransomware heavily utilizes Windows API functions categorized into domains like file operations, networking, memory management, process control, etc.

2.1 Registry Manipulation Functions:

- "NtCreateKey": Low-level API to create/open a registry key.

Purpose: Registry manipulation is usually for persistence or disabling system defenses.

---

2.2 File Operations:

- "CreateFileW", "ReadFile", "WriteFile", "FlushFileBuffers", "FindFirstFileExW", "SetFilePointerEx"

Purpose: These allow the ransomware to access and modify files, essential for encrypting victim data.

Technical Note: The heavy use of "CreateFileW" and "WriteFile" suggests mass file handling, typical for ransomware encryption operations.

---

2.3 Networking and Communication Functions:

- "socket", "connect", "send", "recv", "WSAStartup", "WSACleanup"

Purpose: Establish TCP/IP communications possibly to:

- Communicate with a Command and Control (C2) server
- Exfiltrate stolen information
- Receive encryption keys

Technical Note: "getaddrinfo", "bind", and "accept" imply capabilities for both client and server communication roles.

---

2.4 Process Control:

- "CreateThread", "ExitProcess", "TerminateProcess"

Purpose: Multi-threading and process control to maintain performance during encryption and possibly to terminate interfering processes (e.g., security software).

---

2.5 Memory Management:

- "HeapAlloc", "HeapFree", "HeapReAlloc"

Purpose: Dynamic memory management critical for encrypting files of varying sizes efficiently.

---

2.6 DLL and Resource Handling:

- "LoadLibrary", "FreeLibrary", "GetModuleHandle"

Purpose: Dynamic import of DLLs potentially for obfuscation or modular loading of payload components.

---

2.7 Anti-Debugging and Evasion:

- "IsDebuggerPresent", "QueryPerformanceCounter", "Sleep", "SetUnhandledExceptionFilter"

Purpose:

- Detect if running inside analysis environments.
- Modify behavior or halt execution if under analysis.

Technical Note: "QueryPerformanceCounter" is often used to detect "sleep skipping" techniques in sandboxes.

---

2.8 Cryptographic Functions:

- "CryptGenRandom", "EncodePointer"

Purpose:

- "CryptGenRandom" is crucial for generating secure random keys.
- "EncodePointer" is used to protect sensitive pointers from memory corruption attacks.

---

2.9 Information Gathering Functions:

- "GetSystemInfo", "GetCommandLine", "GetStartupInfoW"

Purpose: Gather system and environment information to tailor the attack based on the system's configuration.

---

 3. Linked DLLs

Observed DLLs:

- "KERNEL32.dll" (Core system functions)
- "USER32.dll" (GUI interaction)
- "crypt32.dll" (old Cryptography algorithms to import such as for the certs etc.)
- "ws2_32.dll" (Networking)
- "secur32.dll", "bcrypt.dll" -- (newly cryptographic algos), "ntdll.dll", etc.

Technical Note: A dependency on "ws2_32.dll" confirms extensive networking functionalities.

---

 4. PDB (Program Database) Artefact

PDB Path Found: "encv2.pdb"

Technical Insight:

- Indicates that the binary was compiled without removing debug symbols.
- This sometimes reveals internal names or developers' paths, aiding attribution.

---

 5. Special Artifact Detection

- No hardcoded registry keys.
- No embedded PE files.
- No unusual artifacts detected.

---

 6. Interesting Strings Analysis

 6.1 Stack Strings Extracted

- Examples: "aI4w", "0001", "TUTU", "8gId", "uespemosarenegylmodnarodsetybdet"

Technical Detail: Stack strings are built at runtime in memory to evade simple static string detection.

 6.2 Tight Strings

- Examples: "78124286", "fefefefe78", "4403900871474942", "3010", "2340172838076674"

Technical Insight: These tight repetitive patterns suggest encrypted configuration or unique IDs.

 6.3 Decoded Strings (via Function Emulation)

- Examples: "RHnL", "aI4w", "t<-}65=&", "E3y3y", "TUTUTUTU"

Technical Insight: Decoded strings appear partially random and may be encryption keys, session identifiers, or internal markers.

Deep Note: RHnL could be an abbreviation or codeword used internally. If systematically reversed or substituted, it might lead to real instructions or keys.

---

 7. YARA Rule Matches

Matched Cryptographic Constants:

- SHA512, SHA3, BLAKE2, Chacha20, SipHash

Networking Indicators:

- TCP socket creation and communication ("network_tcp_listen", "network_tcp_socket", "network_dns")

Anti-Debugging Indicators:

- "IsDebuggerPresent", "Sleep", "QueryPerformanceCounter"

File System Indicators:

- File access patterns matching ransomware behavior ("win_files_operation")

RustyStealer-like Traits:

- Matched some signatures resembling RustyStealer malware (stealing credentials).

---

 8. Section Analysis (Entropy & Structure)

| Section    | Virtual Size | Entropy | Notes                                              |
| ---------- | ------------ | ------- | -------------------------------------------------- |
| .text  	 | 0x187fc0     | 6.32    | High entropy, indicating packed or encrypted code. |
| .rdata 	 | 0x7f5ea      | 5.07    | Data section with strings, function pointers.      |
| .data	     | 0x2088       | 1.82    | Low entropy, likely stores runtime variables.      |
| .pdata     | 0x5364       | 5.86    | Structured exception handling data (SEH).          |
| .reloc     | 0x4038       | 5.42    | Base relocations, normal for portability.          |

Technical Insight: High entropy in ".text" implies that the ransomware either encrypts or compresses itself heavily to prevent easy analysis.

---

 9. Hashes

- MD5: "1289a867fafe321b51a93aa47afaffc9"
- SHA1: "221d0cbd5c7a0c84bb86b4351c552f6efcd4f3b6"
- SHA256: "c6ddc9c2852eddf30f945a50183e28d38f6b9b1bbad01aac52e9d9539482a433"
- IMPHASH: "9448b7f2dfefd2cd32e6d9b27e1ca042"

Purpose: Cryptographic hashes are critical for:

- Identifying the sample uniquely
- Cross-referencing known malware databases

---

 Final Assessment

"pe32ransomware.exe" is a highly sophisticated ransomware sample with:

- Strong evasion techniques (anti-debugging)
- Full networking capability (for C2 communication)
- Solid cryptographic foundation (SHA3, BLAKE2, Chacha20 constants)
- Evidence of packing or encryption (high entropy)

--------------------

Yara rule detection
rule PE32_Ransomware_Detector
{
    meta:
        description = "Detects PE32 Ransomware based on known strings and artifacts"
        author = "analyst"
        reference = "Custom rule based on PE32 ransomware analysis"
        date = "2025-03-28"
        malware_family = "PE32 Ransomware"

  strings:
        $ransom_note = "Your files have been encrypted, and your sensitive data has been exfiltrated"
        $telegram_token = "bot" ascii wide
        $pe32_marker1 = "pe32lockfile.lock"
        $pe32_marker2 = "context.pe32c"
        $pe32_marker3 = "lock.pe32"
        $pe32_extension = ".pe32s"
        $magic_chacha = "expand 32-byte k" ascii wide
        $ransom_contact = "@decryptorsupport" ascii wide
        $drive_prompt = "What drive do you want to encrypt:? (Empty means all)" ascii wide
        $disk_size_prompt = "Drive Size: GB" ascii wide

    condition:
        uint16(0) == 0x5A4D and // PE header (MZ)
        filesize < 10MB and
        5 of ($ransom_note, $telegram_token, $pe32_marker1, $pe32_marker2, $pe32_marker3, $pe32_extension, $magic_chacha, $ransom_contact, $drive_prompt, $disk_size_prompt)
}


---

Telegram bot detection in SIEM

index=your_index_name sourcetype="Sysmon" EventCode=3
| where DestinationHostname LIKE "%.telegram.org%" OR DestinationIP IN ("149.154.167.220", "91.108.4.0/22", "149.154.160.0/20")
| table _time, SourceIP, DestinationIP, DestinationHostname, Image

and corelated with SIEM detection rule logic ----

index=your_index_name sourcetype="Sysmon" EventCode=11
| where FileName LIKE "%.pe32c" OR where FileName LIKE "%.pe32"
| stats count by FileName, TargetFilename, HostName
| where count > 5
| table _time, HostName, FileName, TargetFilename, count


---
1. "pe32lockfile.lock"
- Meaning: A lock file.
- Role in Execution: This is created to mark that encryption has already started or completed — preventing double-encryption or signaling progress.

---

 2. "////////////////\\\\\\\\\\\\\\\\////////"
- Meaning: Visual separator (not code).
- Role: Used in ransom notes or console output for formatting messages clearly.

---

 3. "|7Y8"
- Meaning: Random short token.
- Role: Likely a marker, session ID, or internal encryption round ID.

---

 4. "expand 32-byte k"
- Meaning: Part of the ChaCha20 key expansion.
- Role: Confirms the malware uses ChaCha20 encryption — a very fast, strong symmetric encryption algorithm.

---

 5. "uespemosarenegylmodnarodsetybdet"
- Meaning: Reverse → "detbydesrandomlygeneratedpurpose".
- Role: Indicates that file names or encryption keys are randomly generated for each victim.

---

 6. "General_Categoryme_Cluster_BreakGrapheme_ClusterScript_Extensions"
- Meaning: Unicode metadata.
- Role: Part of underlying string handling libraries — not critical to encryption directly but necessary for properly parsing filenames.

---

 7. "README.txt"
- Meaning: The ransom note file name.
- Role: After encrypting files, ransomware drops a ransom note explaining payment instructions.

---

 8. "Lock file presentpe32lockfile.lockUltraFast Completed"
- Meaning: Console or log message.
- Role: Indicates ultrafast encryption phase completed. "Lock file present" confirms progress.

---

 9. "Drive Size: GB"
- Meaning: Place-holder output during scan.
- Role: Checks disk size before encrypting to optimize encryption strategy (small disks = encrypt all, large disks = selective encryption).

---

 10. "What drive do you want to encrypt:? (Empty means all)"
- Meaning: Malware asking for target drive.
- Role: May have manual targeting functionality for the attacker.

---

 11. UUIDs like "18e1ad78-b4f7-4a53-8c3c-78ace48fdc7f:"
- Meaning: Disk volume or file system UUID.
- Role: Unique identifier for target disks — encryption is organized by UUID internally.

---

 12. "context.pe32cID"
- Meaning: Internal configuration context.
- Role: Likely stores encryption parameters or victim-specific identifiers.

---

 13. "Bad UltraFast State for encryption"
- Meaning: Error message.
- Role: If the encryption state machine fails, malware reports this internally.

---

 14. "Failed to resolve api.telegram.com"
- Meaning: Tried to contact Telegram server.
- Role: For sending victim ID, encryption keys, or providing contact info via Telegram.

---

 15. "chat_idUSER: Armin"
- Meaning: Hardcoded Telegram user or operator name.
- Role: Operator pseudonym: "Armin".

---

 16. FULL RANSOM NOTE Content (Extracted)
> Greetings  
> Your files have been encrypted, and your sensitive data has been exfiltrated.  
> To unlock your files and prevent public disclosure of data a payment is required.

- Meaning: Standard ransom message.
- Role: Psychological pressure on victim: threaten public exposure and demand Bitcoin or cash payment.

---

 17. Pricing Section
- Single servers: $700 - $7000  
- Companies: $10,000 or 2+ BTC

- Meaning: Price depends on victim's importance.
- Role: Typical ransomware pricing tiers based on victim size.

---

 18. Contact Details
- Telegram: "@decryptorsupport"
- Email: "bettercallarmin1@gmail.com"

- Meaning: Channels to negotiate and pay.
- Role: Operator-controlled communications to accept ransom.

---

 19. Public Key Block
- "-----BEGIN PUBLIC KEY----- MIICIjANBgkqhkiG9w0... -----END PUBLIC KEY-----"

- Meaning: RSA Public Key.
- Role: Encrypts the AES/ChaCha keys used for encrypting the files, making it impossible to decrypt files without the attacker's private key.

---

 20. "lock.pe32"
- Meaning: Encrypted file marker.
- Role: Files after encryption might be renamed with ".pe32lock" or ".pe32" extension.

---

 21. Error Strings: Crypto, ASN.1, Decryption
Examples:
- "InvalidEncodingBase64Character"
- "DecryptionVerificationMessageTooLong"
- "InternalLabelTooLong"

- Meaning: Crypto and ASN.1 parsing errors.
- Role: Shows robust error handling for cryptography, especially with public key formats and Base64 data.

---

 22. Filenames/Backup Extensions Mentioned
- ".sqlite3", ".psql", ".vhdx", ".bak", ".mdb", ".xml", ".json", ".yaml", ".bson", ".tar", ".zip", etc.

- Meaning: Targeted filetypes.
- Role: Prioritize backup files and databases for encryption because they are high-value targets.

---

 23. Encryption Context
- Terms like "AES", "ChaCha20", "static bind failure", "encryption chunk skipping".

- Meaning: Encryption internal terminology.
- Role: Controls how encryption keys and chunks are generated and managed.

---

 24. Unicode Errors, Regex Libraries, Parsing Engines
- Meaning: Some parts of the malware use complex parsers and Unicode libraries.
- Role: Likely related to safely parsing filenames, validating user input, or decrypting configuration blobs.

---

 25. Low-level Windows API Imports
Examples:
- "NtCreateKeyedEvent"
- "HeapAlloc"
- "CryptGenRandom"
- "CreateFileW"
- "EncryptMessage"
- "AcceptSecurityContext"

- Meaning: These functions show direct Windows system interaction.
- Role: Used for file access, memory management, cryptographic ops, and network communication.

----------------------------------------------------

 Is This ChaCha20?
The string 'expand 32-byte k' is strongly associated with the ChaCha20 encryption algorithm, specifically in its key expansion process. Here's why:

1. ChaCha20's Key Setup  
   - ChaCha20 uses a 256-bit (32-byte) key and a 96-bit nonce.  
   - The constant '"expand 32-byte k"' (or '"expand 16-byte k"' for 128-bit keys) is part of the initial state when setting up the cipher.  
   - This string appears in the first 16 bytes of the ChaCha20 block function.  

2. Why It Suggests ChaCha20  
   - Other ciphers (like AES or Salsa20) do not use this exact string.  
   - Salsa20 uses '"expand 32-byte k"' as well, but ChaCha20 is a modified version of Salsa20, and this constant remains the same.  

Conclusion: Yes, this strongly indicates ChaCha20 is being used for encryption in this ransomware.  

---

 What Is the String 'uespemosarenegylmodnarodsetybdet'?
This appears to be a modified or corrupted version of the expected ChaCha20 constant.  

 Expected vs. Observed
- Correct ChaCha20 constant:  
  '"expand 32-byte k"' (ASCII: '0x65, 0x78, 0x70, 0x61, 0x6E, 0x64, 0x20, 0x33, 0x32, 0x2D, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6B')  

- Observed string:  
  '"uespemosarenegylmodnarodsetybdet"'  

 Possible Explanations
1. Obfuscation  
   - The malware author may have scrambled or XORed the constant to evade signature-based detection.  
   - Some ransomware families modify constants to avoid YARA rules.  

2. Encoding Issue  
   - If the binary was dumped incorrectly, the string might appear corrupted.  
   - Could be a base64 or XOR transformation of the original.  

3. Custom Cipher Variant  
   - The attacker might have tweaked ChaCha20 slightly (unlikely, but possible).  

---

 What Does This Mean for Decryption?
1. If ChaCha20 is used properly:  
   - The ransomware likely generates a random key + nonce per file.  
   - The key is encrypted with RSA (the public key you found).  
   - Without the private RSA key, decryption is impossible unless:  
     - The ransomware has a flaw (e.g., reusing nonces).  
     - The ChaCha20 implementation is weak (unlikely).  

2. If the string is modified:  
   - The malware might be using a customized ChaCha20, making decryption harder.  
   - Reverse-engineering would be needed to see how it differs.  

