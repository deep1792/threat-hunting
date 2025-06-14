#!/bin/bash
set -euo pipefail

REPORT_BASE="k8s-threat-hunt-report"
REPORT_TXT="${REPORT_BASE}.txt"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Start report
{
  echo "================= Kubernetes Threat Hunting Report ================="
  echo "Date & Time: $DATE"
  echo "===================================================================="
  echo ""
} > "$REPORT_TXT"

function log() {
  echo -e "$1"
}

function section() {
  echo -e "\n$1" | tee -a "$REPORT_TXT"
  echo "--------------------------------------------------------------------" >> "$REPORT_TXT"
}

log "🔍 Initial Reconnaissance"
section " Initial Reconnaissance"
echo "- All Pods (default + wide output):" >> "$REPORT_TXT"
kubectl get pods >> "$REPORT_TXT"
kubectl get pods -A -o wide >> "$REPORT_TXT"

echo "- Describe pod (reverse shell path if exists):" >> "$REPORT_TXT"
kubectl describe pod reverse-shell/backdoor-shell-29154692-mqx2f/lateral-move/reverse-shell/token-stealer/victim-app >> "$REPORT_TXT" 2>/dev/null || echo "Pod path not found" >> "$REPORT_TXT"

echo "- Node details:" >> "$REPORT_TXT"
kubectl get nodes -o wide >> "$REPORT_TXT"

echo "- Services list:" >> "$REPORT_TXT"
kubectl get svc -A >> "$REPORT_TXT"

echo "- Endpoints list:" >> "$REPORT_TXT"
kubectl get ep -A >> "$REPORT_TXT"

echo "- Raw Pod JSON (privilege hunting):" >> "$REPORT_TXT"
kubectl get pods -A -o json >> "$REPORT_TXT"

echo "- Pods using host network:" >> "$REPORT_TXT"
kubectl get pods -A -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.name}{"\n"}{end}' >> "$REPORT_TXT"

echo "- CronJobs across all namespaces:" >> "$REPORT_TXT"
kubectl get cronjobs -A >> "$REPORT_TXT"
echo "- Describe example CronJob (backdoor-shell):" >> "$REPORT_TXT"
kubectl describe cronjob backdoor-shell >> "$REPORT_TXT" 2>/dev/null || echo "CronJob not found" >> "$REPORT_TXT"

echo "- Secrets overview:" >> "$REPORT_TXT"
kubectl get secrets >> "$REPORT_TXT"
kubectl describe secret db-secret >> "$REPORT_TXT" 2>/dev/null || echo "db-secret not found" >> "$REPORT_TXT"
kubectl describe pod victim-app >> "$REPORT_TXT" 2>/dev/null || echo "victim-app not found" >> "$REPORT_TXT"
kubectl get secret db-secret -o jsonpath="{.data.password}" | base64 --decode >> "$REPORT_TXT" 2>/dev/null || echo "Password not found or decode failed" >> "$REPORT_TXT"

echo "- Service Account abuse possibilities:" >> "$REPORT_TXT"
kubectl describe serviceaccount >> "$REPORT_TXT"
kubectl get clusterrolebinding >> "$REPORT_TXT"

echo "- Privileged pod check (via JSONPath):" >> "$REPORT_TXT"
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.privileged}{"\n"}{end}' >> "$REPORT_TXT"

section " Advanced Threat & CVE Detection"
echo "- Check for containers running as root (security risk):" >> "$REPORT_TXT"
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.runAsUser}{"\n"}{end}' >> "$REPORT_TXT"

echo "- Search for mount paths that expose host filesystem (hostPath):" >> "$REPORT_TXT"
kubectl get pods -A -o json | jq '.items[].spec.volumes[]? | select(.hostPath) | .hostPath.path' >> "$REPORT_TXT" 2>/dev/null || echo "No hostPath volumes found" >> "$REPORT_TXT"

echo "- Detect risky capabilities (NET_ADMIN, SYS_ADMIN):" >> "$REPORT_TXT"
kubectl get pods -A -o json | jq '..|.capabilities? // empty | select(.add != null) | .add[]' | grep -E 'NET_ADMIN|SYS_ADMIN' >> "$REPORT_TXT" 2>/dev/null || echo "No risky capabilities found" >> "$REPORT_TXT"

echo "- Check for anonymous access to API server:" >> "$REPORT_TXT"
kubectl get clusterrolebinding | grep -i anonymous >> "$REPORT_TXT" || echo "No anonymous access clusterrolebindings found" >> "$REPORT_TXT"

echo "- Latest CVEs potentially affecting common base images (Alpine, Ubuntu):" >> "$REPORT_TXT"
echo "CVE-2024-3094 (XZ Backdoor in Ubuntu) - Check Ubuntu-based containers." >> "$REPORT_TXT"
echo "CVE-2024-21626 (runc escape) - Containers using runc may be vulnerable." >> "$REPORT_TXT"
echo "CVE-2024-22356 (containerd escalation) - Verify containerd version." >> "$REPORT_TXT"
echo "Manually validate image security with: trivy image <image-name>" >> "$REPORT_TXT"

section "️Trivy Image Scan"
echo "- Scanning all running images with Trivy (top 10):" >> "$REPORT_TXT"
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u | head -n 10 | while read -r img; do
  echo "Scanning: $img" >> "$REPORT_TXT"
  trivy image --scanners vuln --severity HIGH,CRITICAL --quiet "$img" >> "$REPORT_TXT" 2>/dev/null || echo "Failed to scan $img" >> "$REPORT_TXT"
done

echo "- Suspicious network behavior (e.g., external IPs in container ENV):" >> "$REPORT_TXT"
kubectl get pods -A -o json | jq '..|.env? // empty | .[]? | select(.value | test("\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."))' >> "$REPORT_TXT" 2>/dev/null || echo "No suspicious IPs in ENV found" >> "$REPORT_TXT"

section "Kubernetes Audit Log Analysis (basic keywords)"
echo "- Grepping for risky commands in audit log (create, exec, secrets, delete):" >> "$REPORT_TXT"
AUDIT_FILE="/var/log/kubernetes/audit.log"
if [[ -f "$AUDIT_FILE" ]]; then
  grep -Ei '"verb":"(create|exec|delete|get|update)"' "$AUDIT_FILE" | grep -Ei 'secret|token|exec|command|shell' >> "$REPORT_TXT" || echo "No risky audit entries found" >> "$REPORT_TXT"
else
  echo "Audit log file not found: $AUDIT_FILE" >> "$REPORT_TXT"
fi

section "Threat Hunting Completed - Review full report: $REPORT_TXT"
echo ""
