# 🧠 Cyber Concepts Behind the Phases

### 🔨 PHASE 1: Base Framework for CNAPP-lite
* Set up a modular project structure
* Create a simulated AWS environment (with moto)
* Build an S3 scanner
* Export results in frontend-compatible JSON
* Add a Dockerfile for easy local execution

||Concept|What It Means|Why It Matters||
|---|---|---|---|---|
|| `S3 (Simple Storage Service)` | AWS’s cloud storage — like folders in the cloud   | Misconfigured buckets can expose sensitive data||
|| `ACL (Access Control List)`   | Old-school permission model on S3 buckets| Allows public access if not configured carefully||
|| `Public buckets`| Buckets readable by “everyone” on the internet| Often the source of data breaches (e.g., Verizon 2017)||
|| `moto`| Python library that mocks AWS services| Lets you simulate AWS environments without a real cloud account ||
|| `boto3`| Official AWS Python SDK| You’ll use this to talk to real AWS later||
|| `Risk Findings`| Identified vulnerabilities or misconfigurations| Help prioritize what to fix first||
|| `JSON Reports`| Machine-readable output that can be shown in a UI | Makes the results visual and reusable||
|| `MITRE ATT&CK mapping`| Security tactics and techniques| Adds professionalism and clarity to each finding||
|| `Docker`| Lightweight containers to run apps consistently| Makes deployment easy anywhere later (cloud, laptops, CI/CD)||

---

### 📚 Phase 2 Knowledge

| AWS Component   | What You're Scanning               | Why It Matters             |
| --------------- | ---------------------------------- | -------------------------- |
| S3 Buckets      | Public access, encryption, logging | Prevent data leaks         |
| IAM Roles       | Wildcard permissions (`*:*`)       | Stops privilege escalation |
| EC2 Instances   | Secrets in user data               | Secrets exposure risk      |
| Security Groups | Open ports to the world            | Prevent remote attacks     |


| 🔐 AWS Service | What You're Learning                                                                                       |
| -------------- | ---------------------------------------------------------------------------------------------------------- |
| **IAM**        | Identity & Access Management. Policies like `*:*` are dangerous because they grant **unrestricted power**. |
| **EC2**        | Elastic Compute Cloud — virtual machines. Risk factors include:                                            |
| **Security Groups** | Firewalls around EC2 instances. Misconfigurations like `0.0.0.0/0` expose services to the entire internet. |


* Exposed SSH (port 22)
* Secrets in user data (common mistake!)
* Risky IAM roles attached:
    1. **Security Groups:** | Firewalls around EC2. `0.0.0.0/0` means open to the world — a massive red flag 🚨
    2. **Least Privilege** | Best practice: give users and machines only the permissions they need — nothing more.
    3. **User Data** | Scripts passed to EC2 on boot. These often accidentally include passwords, AWS secrets, or SSH keys.
    4. **Correlation Potential** | If an EC2 uses a wildcard IAM role and accesses an S3 bucket — attacker could move laterally.

---

### 🔑 Key Security Concepts

#### **Security Groups**
- **What It Is**: A virtual firewall that controls inbound and outbound traffic to AWS resources like EC2 instances.
- **Why It Matters**: Misconfigured security groups (e.g., allowing `0.0.0.0/0` on port 22) can expose sensitive services to the internet, making them vulnerable to attacks.
- **Best Practices**:
  - Restrict access to specific IP ranges.
  - Use least privilege by allowing only necessary ports and protocols.

#### **S3 Scanner**
- **What It Is**: A tool to scan S3 buckets for misconfigurations.
- **Why It Matters**: Misconfigured S3 buckets are a common source of data breaches.
- **What It Detects**:
  - Publicly accessible buckets.
  - Missing encryption.
  - Disabled versioning.
  - Lack of logging.
- **Example Risks**:
  - Public buckets exposing sensitive files.
  - Buckets without encryption, making data vulnerable to unauthorized access.

#### **IAM (Identity and Access Management)**
- **What It Is**: A service that controls access to AWS resources by managing users, roles, and policies.
- **Why It Matters**: Misconfigured IAM policies (e.g., `*:*`) can grant unrestricted access, leading to privilege escalation or data breaches.
- **Best Practices**:
  - Use **least privilege**: Grant only the permissions required for a task.
  - Avoid wildcard permissions (`*:*`) in policies.
  - Rotate access keys regularly and avoid embedding them in code.

#### **EC2 (Elastic Compute Cloud)**
- **What It Is**: A service that provides virtual machines in the cloud.
- **Why It Matters**: Misconfigured EC2 instances can expose sensitive data or services to attackers.
- **Risk Factors**:
  - **Exposed SSH (port 22)**: Leaving SSH open to the internet (`0.0.0.0/0`) makes the instance vulnerable to brute-force attacks.
  - **Secrets in User Data**: User data scripts often contain sensitive information like passwords or AWS credentials.
  - **Overly Permissive IAM Roles**: Attaching roles with excessive permissions can allow attackers to escalate privileges.
  - **Lateral Movement**: If an EC2 instance accesses an S3 bucket with a wildcard IAM role, attackers can exploit this to move laterally within the environment.
- **Best Practices**:
  - Restrict SSH access to specific IP ranges.
  - Avoid storing secrets in user data scripts.
  - Use IAM roles with the least privilege required for the instance.

---

### 🚀 Why This Knowledge Matters
Understanding these concepts helps you:
- Secure cloud environments by identifying and mitigating risks.
- Build cloud-native applications with security in mind.
- Prepare for real-world scenarios where misconfigurations can lead to breaches.

---

| Port        | Purpose                    | Risk if Exposed                                      |
| ----------- | -------------------------- | ---------------------------------------------------- |
| `22`        | SSH (Linux Admin Access)   | Full control of instance                             |
| `3389`      | RDP (Windows Admin Access) | Full control of Windows EC2                          |
| `80/443`    | Web traffic                | OK for web servers, risky otherwise                  |
| `0-65535`   | All ports open             | Nightmare scenario 💀                                |
| `0.0.0.0/0` | Open to anyone             | Must be combined with sensitive ports to detect risk |
