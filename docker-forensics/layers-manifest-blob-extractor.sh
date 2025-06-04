#!/bin/bash

# Directory where the OCI image was extracted
OCI_DIR="/home/j0ck3r/Downloads/malware/malware-samples/docker-malicious/manifest-attacker/"
LAYER_DIR="layers"

mkdir -p "$LAYER_DIR"
cd "$OCI_DIR" || exit 1

# Read manifest.json
manifest_file="manifest.json"
layer_digests=$(jq -r '.[0].Layers[]' "$manifest_file")

layer_num=1

echo "[*] Extracting layers from manifest.json..."
for digest in $layer_digests; do
	# Clean up the digest path
	clean_digest=$(basename "$digest")
	tarball="blobs/sha256/$clean_digest"
	
	if [ -f "$tarball" ]; then
		out_dir="../$LAYER_DIR/layer$layer_num"
		mkdir -p "$out_dir"
		echo "  → Extracting layer $layer_num to $out_dir"
		tar -xf "$tarball" -C "$out_dir"
	else
		echo "    Layer tarball not found: $tarball"
	fi

	((layer_num++))
done

cd ..

echo "[*] Extraction complete."
echo "[*] Starting basic IOC checks..."

# Basic forensic IOC sweep
for d in "$LAYER_DIR"/*; do
	echo "---- Analyzing $(basename "$d") ----"
	
	find "$d" -type f \( -name "*cron*" -o -name "*bash_history*" -o -name "*.sh" -o -name "*.service" \) -print

	# Optional: grep for reverse shells or suspicious commands
	grep -rE "nc -e|bash -i|curl|wget|/dev/tcp" "$d" 2>/dev/null
	echo
done

echo " Analysis complete. Layers in $LAYER_DIR/"

