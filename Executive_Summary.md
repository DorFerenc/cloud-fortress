# Executive Summary: 						Dor Ferenc | 11.05.25

* **Project Title:** CNAPP-lite – Cloud Misconfiguration Scanner
* **Project Type:** Cloud Security, Visibility, and Automation Tool
* **Interface:** Web Dashboard (Streamlit) with optional CLI
* **Language:** Python
* **Primary Use Case:** Scan AWS environments (simulated or real) to detect security misconfigurations, visualize risk exposure, and provide actionable remediation insights.

---
### 🎯 Objective
CNAPP-lite is a Python-based tool designed to give full visibility into an AWS environment and automatically detect common cloud misconfigurations. It helps users identify and understand security risks like public S3 buckets, overly permissive IAM roles, and open firewall ports. The tool is built for learning cloud security, improving DevSecOps skills, and demonstrating real-world security thinking in interviews or portfolios.

---
### 🔐 Core Features
* One-click “Scan Now” action from the web dashboard
* Scans AWS resources using real or simulated (moto) environments
* Detects misconfigurations in S3, IAM, EC2, and Security Groups
* Shows all resources with risky ones prioritized visually
* Cross-links issues across services (e.g. EC2 → IAM Role → S3 Access)
* Generates detailed findings with severity, risk context, and fix suggestions
* Exportable reports
* Modular and extendable codebase

---
### 🔍 Visibility, Alerts & Cross-Service Correlation
* CNAPP-lite doesn’t just alert on risks — it shows the full environment view with context.
    * For every AWS service scanned, it provides:
    * ✅ **Visibility:** Full list of all resources
    * 🔴 **Alerts:** Misconfigured or high-risk items shown at the top
    * 🧠 **Context:** Why the issue matters and how to fix it
    * 🔗 **Cross-Data Mapping:** Links between users, machines, policies, and networks
    * 📊 **Optional Metrics:** Usage data (e.g., CPU, memory, network) where available

---
### 📊 CNAPP-lite Data Visibility & Alerting Plan
#### 🪣 S3 Buckets
* ✅ All buckets: name, region, owner, encreyption
* 🔴 Public buckets: flagged if ACL or policy is public, unencrypted buckets.
* 🔒 Additional: encryption, versioning, logging
* 🔗 Cross-ref: highlight which IAM roles or EC2s access each bucket
#### 👤 IAM Users & Roles
* ✅ All IAM users/roles: name, type, attached policies, MFA status
* 🔴 Admin roles or wildcard permissions (*:*)
* 🔒 Additional: MFA status, last login
* 🔗 Cross-ref: list EC2 instances or S3 buckets this identity affects
#### 🌐 EC2 Security Groups
* ✅ All groups: name, open ports, allowed ports, source IPs
* 🔴 Open-to-World ports (e.g., 22/3389 to 0.0.0.0/0), SSH/RDP
* 🔒 Additional: associated EC2 instances
* 🔗 Cross-ref: show which EC2 instances use each group
* 🖥️ EC2 Instances
* ✅ All EC2s: name, ID, type, tags
* 🔴 At-risk instances: flagged based on open ports, secrets, or overprivileged roles, open security group, user data contains secrets, IAM role attached has admin or wildcard permissions.
* 🔒 Additional: region, launch time, role attached
* 🔗 Cross-ref: List IAM roles attached to instance and whether they're risky, List security groups and public port exposure, Link to any S3 bucket accessed using that role.
#### 🧾 Secrets in Metadata
* ✅ All user data and tags scanned
* 🔴 Secrets found: regex matches for `password=, AKIA, token=`
* 🔒 Additional: source, resource, and region
* 🔗 Cross-ref: map to EC2 instance and IAM role using the secret

---
### 🔗 Example of Cross-Service Insight
"EC2 instance `prod-web-server` has SSH exposed to the internet and is using IAM role `DevOpsAdmin`, which has `AdministratorAccess` without MFA. The same role can also write to the S3 bucket `company-logs`, which is publicly readable."
* This kind of connection shows:
    * 🔥 Risk exposure (EC2 attack path)
    * 🚪 Entry point (open port)
    * 🧍 Escalation method (IAM role with wildcard access)
    * 📦 Lateral movement (bucket write access)

---
### 💡 Why This Matters
CNAPP-lite bridges the gap between scanning and understanding. It helps:
Devs and engineers see what exists in their cloud and what’s dangerous
Security teams correlate issues across IAM, network, and storage
Students and entry-level professionals build cloud security intuition
This is not just a scanner — it’s a **training-grade visibility tool** that demonstrates real knowledge of **how misconfigurations happen and why they matter.**
