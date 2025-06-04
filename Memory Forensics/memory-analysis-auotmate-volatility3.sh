#!/bin/bash

MEM_IMAGE="/home/j0ck3r/Downloads/malware/malware-samples/medusa-win11/H4CKZ0N3-20250520-134841.raw" #Insert the image path
YARA_RULE="custom-yara-detection.yar"     #Insert the custom yara detection file path
DUMP_DIR="vol_output"      #Name of the directory 
mkdir -p "$DUMP_DIR"

echo "[*] Running Medusa Ransomware Triage with   python3 vol.pyatility 3..."
echo "[+] Memory Image: $MEM_IMAGE"
echo "[+] Output Directory: $DUMP_DIR"
echo

# Process listing
echo "[*] Step 1: Listing processes"
python3 vol.py -f "$MEM_IMAGE" windows.pslist | tee "$DUMP_DIR/pslist.txt"

# Check suspicious command lines
echo "[*] Step 2: Checking command lines"
python3 vol.py -f "$MEM_IMAGE" windows.cmdline | tee "$DUMP_DIR/cmdline.txt"

# DLL list (look for reflectively injected or suspicious DLLs)
echo "[*] Step 3: DLLs loaded into memory"
python3 vol.py -f "$MEM_IMAGE" windows.dlllist | tee "$DUMP_DIR/dlllist.txt"

# Handle list (look for ransom notes or encrypted files)
echo "[*] Step 4: Open file handles"
python3 vol.py -f "$MEM_IMAGE" windows.handles | tee "$DUMP_DIR/handles.txt"

# Scan for ransom-related files
echo "[*] Step 5: Scanning memory for ransom-related files"
python3 vol.py -f "$MEM_IMAGE" windows.filescan | grep -iE "readme|decrypt|medusa|ransom" | tee "$DUMP_DIR/filescan_ransom.txt"

# Malfind: injected code regions
echo "[*] Step 6: Detecting injected code"
python3 vol.py -f "$MEM_IMAGE" windows.malfind | tee "$DUMP_DIR/malfind.txt"
#python3 vol.py -f "$MEM_IMAGE" windows.malfind --dump-dir "$DUMP_DIR/malfind" | tee "$DUMP_DIR/malfind.txt"

# Registry hives
echo "[*] Step 7: Listing registry hives"
python3 vol.py -f "$MEM_IMAGE" windows.registry.hivelist | tee "$DUMP_DIR/hives.txt"

# Run keys (persistence)
echo "[*] Step 8: Checking autorun persistence"
for hive in $(grep -i 'software' "$DUMP_DIR/hives.txt" | awk '{print $1}'); do
python3 vol.py -f "$MEM_IMAGE" windows.registry.printkey --offset "$hive" --key "Microsoft\\Windows\\CurrentVersion\\Run" | tee -a "$DUMP_DIR/autoruns.txt"
done

# Services (check for rogue services)
echo "[*] Step 9: Checking services for persistence"
for hive in $(grep -i 'system' "$DUMP_DIR/hives.txt" | awk '{print $1}'); do
python3 vol.py -f "$MEM_IMAGE" windows.registry.printkey --offset "$hive" --key "ControlSet001\\Services" | tee -a "$DUMP_DIR/services.txt"
done

# YARA scan
if [[ -f "$YARA_RULE" ]]; then
  echo "[*] Step 10: Scanning memory with Medusa YARA rule"
    python3 vol.py -f "$MEM_IMAGE" yara --yara-file "$YARA_RULE" | tee "$DUMP_DIR/yara_medusa.txt"
else
  echo "[!] Skipping YARA scan – rule file not found: $YARA_RULE"
fi

echo "[✔] Triage Complete. Results saved to: $DUMP_DIR"
