Docker complete forensic analysis (end-to-end)

 What is Docker?

Docker is an open-source platform that enables you to automate the deployment, scaling, and management of applications using containerization.

---

 Why Use Docker?

 Consistency across environments (dev, test, prod)
 Faster development cycles
 Lightweight and portable containers
 Microservices architecture support

---

 Key Concepts & Technical Terms

| Term              | Description                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------- |
| Container    		| A lightweight, standalone executable package that includes everything needed to run a piece of software. |
| Image         	| A read-only template used to create containers. this contains app code,libraries, interpreters, etc.	   |
| Dockerfile    	| A script containing a series of instructions used to build a Docker image.                               |
| Docker Hub    	| A cloud-based registry where Docker users can share images.                                              |
| Docker Engine 	| The runtime that builds and runs Docker containers.                                                      |
| Volume        	| A persistent storage mechanism used by containers.                                                       |
| Bind Mount    	| A specific file or directory on the host is mounted into the container.                                  |
| Network       	| A virtual network to allow communication between Docker containers.                                      |
| Registry      	| A place where Docker images are stored and distributed (e.g., Docker Hub, private registry).             |
| Port Binding  	| Maps container ports to host machine ports.                                                              |

---

 Docker Architecture

'''
+-------------------------+
|     Docker Client       |
+-----------+-------------+
            |
            v
+-----------+-------------+
|     Docker Daemon       |
+-----------+-------------+
            |
            v
+-----------+-------------+
| Docker Objects (Images, |
| Containers, Volumes,    |
| Networks)               |
+-------------------------+
'''

---

 Basic Docker Workflow

1. Write a Dockerfile
2. Build an image from Dockerfile
3. Run a container from the image
4. Push the image to a registry (optional)
5. Deploy the container on other machines

---

 Common Use Cases

 Developing microservices
 Running databases locally
 Automating CI/CD pipelines
 Isolated testing environments

----------------------------------------

Docker Components
  Client

| Component      | Explanation                                   |
| -------------- | --------------------------------------------- |
| 'docker build' | Builds a Docker image from a Dockerfile.      |
| 'docker push'  | Uploads a local image to a Docker registry.   |
| 'docker run'   | Creates and starts a container from an image. |

---

  Host

| Component      | Explanation                                                                        |
| -------------- | ---------------------------------------------------------------------------------- |
| Daemons    	 | The Docker Engine (daemon) runs in the background to manage containers and images. |
| Containers     | Running instances of Docker images that encapsulate applications and dependencies. |
| Images         | Read-only templates with instructions to create containers.                        |

---

  Registry

| Component        | Explanation                                                     |
| ---------------- | --------------------------------------------------------------- |
| Repositories 	   | Collections of related Docker images (often tagged by version). |
| Notary           | Provides image signing and verification for trusted content.    |

----------------------------------------------------------

Difference between Docker (container) && VMWare (Hypervisor)

Here's a clear comparison of Docker (Containerization) vs VMware (Hypervisor/Virtualization):

---

Docker vs VMware: Key Differences

| Feature             | Docker (Containerization)                              	    | VMware (Hypervisor/Virtualization)                             |
| ------------------- | ----------------------------------------------------------- | -------------------------------------------------------------- |
| Technology Type 	  | OS-level virtualization                                     | Hardware-level virtualization                                  |
| Isolation Level 	  | Process-level isolation (shares host OS kernel)             | Full OS isolation (each VM runs its own OS)                    |
| Boot Time       	  | Very fast (seconds)                                         | Slower (minutes)                                               |
| Resource Usage  	  | Lightweight (uses less RAM and CPU)                         | Heavy (each VM needs OS + app resources)                       |
| OS Dependency   	  | Containers must use the same OS family as host              | VMs can run completely different OSes (e.g., Linux on Windows) |
| Performance     	  | Near-native performance due to lack of full OS overhead     | Slightly reduced due to full OS emulation                      |
| Portability     	  | Highly portable across platforms (write once, run anywhere) | Less portable due to OS/hardware dependencies                  |
| Use Case        	  | Ideal for microservices, CI/CD, cloud-native apps           | Ideal for legacy apps, full OS testing, running multiple OSes  |
| Example Tool    	  | Docker                                                      | VMware Workstation, vSphere, ESXi                              |
| Image Format    	  | Docker Image                                                | VM Disk Image (e.g., VMDK)                                     |

Summary:

 Docker is best for fast, scalable, lightweight application deployment using containers.
 VMware is best for running multiple operating systems with stronger isolation using virtual machines.

-----------------------------------------------------------------
Why forensics in Docker?

 1. Minimal Visibility
	What It Means:
	Containers are lightweight and fast, but they don’t provide the same visibility as full VMs. Traditional monitoring and security tools may not see inside containers unless specifically designed for it.

	 Why It's Dangerous:
	Processes inside containers can run unnoticed by host-level tools.

	If logs are not externalized, malicious activity may vanish once a container is destroyed.

	 Example:
	An attacker exploits a web app inside a container. Since the container lacks audit logging and runs in a temporary state, the entire attack leaves no forensic trail after the container stops.

 2. Container Breakouts
	These are vulnerabilities that allow an attacker to escape a container and gain access to the host OS — a major breach of the Docker security model.

	 Notable CVEs:
	 CVE-2016-5195 (Dirty COW)
	Exploit: Privilege escalation vulnerability in the Linux kernel.
	Impact: A user in a container could write to read-only memory and gain root access on the host.

	 CVE-2017-5123
	Exploit: Linux kernel vulnerability (memory management issue).
	Impact: Enabled container escape and root privilege escalation.

	 CVE-2014-9357
	Exploit: Docker command-line injection vulnerability via crafted image paths.

	Impact: Could lead to arbitrary code execution on the host.

	 Real-World Consequence:
	An attacker who escapes a container can access host system resources, other containers, secrets, or even take over the entire node in a Kubernetes cluster.

 3. Leverage for Persistence & Lateral Movement
	 What It Means:
	Once inside a container or host, attackers often plant backdoors or malicious containers to maintain persistence or move laterally across systems.

	 How Attackers Do It:
	Deploy a new container that communicates with a C2 server.

	Use Docker socket (/var/run/docker.sock) to control other containers.

	Exploit shared networks or volumes to access secrets from other containers.

	 Example:
	If an attacker compromises a Jenkins container, they could:

	Modify the Jenkins build pipeline to deploy a reverse shell

	Use credentials stored in the container to access the Git repo or production DB

	Pivot to other containers using the shared Docker network

 4. Source Poisoning & Supply Chain Attacks
	 What It Means:
	Attackers inject malware into public Docker images or dependencies, which are then unknowingly pulled and used by developers.

	 Example: Malicious Docker Images
	In 2021, over 30 malicious Docker images with cryptominers were downloaded over 20 million times.

	Images appeared to be legit (e.g., ubuntu-nginx, alpine-python) but contained malicious scripts.

	 Supply Chain Attack:
	Compromising a base image (e.g., node:14) or upstream dependency like npm package

Example: SolarWinds breach, though not Docker-specific, highlighted how dangerous trusted dependency attacks can be

 5. Vulnerabilities as Users and Providers
	 Users:
	Misconfigured Dockerfiles (e.g., FROM root, exposing ports)

	Using --privileged flag or mapping Docker socket inside containers

	 Providers:
	Cloud vendors hosting insecure registries

	Official images with outdated libraries (e.g., OpenSSL, glibc vulnerabilities)

	 Real-World:
	A cloud-based CI/CD pipeline might run Docker with elevated privileges. If the CI runner is compromised, all containers and secrets in the pipeline could be exposed.

 6. IP, Credential & Data Leaks in Public Repos
	 What It Means:
	Sensitive data often ends up in Docker images and gets pushed to public registries like Docker Hub — unintentionally.

	 Common Mistakes:
	Hardcoded credentials in ENV or RUN commands

	.env, SSH keys, or config files left in build context

	.dockerignore not properly configured

		Case-studies
		
		1. RWTH Aachen University Study (2023)

			Summary: Researchers analyzed 337,171 Docker images and identified that 8.5% contained sensitive data, including 52,107 valid private keys and 3,158 distinct API secrets. Notably, 95% of the exposed private keys and 90% of API secrets were found in single-user images, indicating unintentional leaks.

			Key Findings:
				Exposed keys were actively used, compromising over 275,000 TLS and SSH hosts.
				22,082 compromised certificates relied on these keys, with 61% being self-signed.
			https://arxiv.org/abs/2307.03958
			
			
		2. Sysdig Threat Research Team Analysis (2022)

			Summary: Sysdig's analysis of over 250,000 Linux images on Docker Hub revealed that many contained embedded secrets, such as API keys and SSH keys, which could be exploited by attackers.

			Key Findings:
				Malicious images often disguised themselves as legitimate software through typosquatting.
				Some images contained cryptocurrency miners and other malicious payloads.
				
			https://sysdig.com/blog/analysis-of-supply-chain-attacks-through-public-docker-images/
			
		3. BleepingComputer Report (2022)

			Summary: An investigation uncovered over 1,600 publicly available Docker Hub images that hid malicious behavior, including cryptocurrency miners and embedded secrets that could serve as backdoors.

			Key Findings:
				Attackers leveraged these images to compromise systems by embedding malicious code and secrets.
		
		https://www.bleepingcomputer.com/news/security/docker-hub-repositories-hide-over-1-650-malicious-containers/


