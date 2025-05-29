# CloudFortress: Cloud Security Automation

CloudFortress is a Python-based CNAPP-lite scanner engineered for DevSecOps teams, security engineers, and cloud architects to **automate detection**, **visualize risk**, and **accelerate remediation** in AWS environments.

## What we scan

### 🧑‍💼 IAM Roles
- **Over-permissive policies**: Identifies roles with wildcard actions (`"Action": "*"`) or resources (`"Resource": "*"`).
- **Privilege escalation paths**: Detects `iam:PassRole` and other dangerous actions that let a user swap into higher-privilege roles.
- **Missing MFA enforcement**: Flags policies lacking MFA conditions on sensitive operations.
- **Unused roles**: Spots roles that have never been used, reducing your attack surface.

> **Why it matters:** Over-privileged or stale IAM roles are a top entry point for attackers to escalate privileges or move laterally in your cloud environment.

---

### 🪣 S3 Buckets
- **Public ACLs & policies**: Flags buckets open to “AllUsers” via ACL or `"Principal": "*"` policies.
- **Encryption status**: Checks for server-side encryption (AES256 or KMS).
- **Versioning**: Ensures versioning is enabled to recover from accidental deletions.
- **Access logging**: Verifies that bucket access logs are being captured.

> **Why it matters:** Misconfigured S3 buckets are one of the leading causes of data leaks and compliance failures.

---

### 🖥️ EC2 Instances
- **Secrets in user data**: Detects embedded passwords or AWS keys in launch scripts.
- **Open SSH/RDP ports**: Flags security group rules allowing port 22/3389 from `0.0.0.0/0`.
- **IMDSv1 enabled**: Finds instances still allowing token-less metadata access (risk of SSRF data theft).

> **Why it matters:** Exposed instance metadata or user-data secrets let attackers snatch credentials and pivot deeper into your network.

---

### 🌐 Security Groups
- **Ingress from anywhere**: Flags any rule with `0.0.0.0/0` and sensitive ports (e.g., 22, 3389, 3306).
- **Wide port ranges**: Detects `0-65535` openings.
- **Unrestricted egress**: Finds outbound rules to the entire internet.
- **Duplicate rules**: Collapses repeated rules, bumping severity to reflect compounded risk.

> **Why it matters:** Overly permissive firewall rules are a direct path for attackers to reach and exfiltrate resources.

---


## Key Features
- **Comprehensive Coverage**: Programmatic scans of S3 buckets, IAM roles, EC2 instances & Security Groups.
- **Actionable Insights**: Prioritized findings with **risk severity**, **MITRE ATT&CK mapping**, and **fix recommendations**.
- **Flexible Execution**: Seamlessly toggle between **real AWS** (boto3) and **simulated environments** (moto).
- **Modular & Extensible**: Clean, well-documented Python modules for easy integration and feature growth.

## Technical scope
Cloud Security · DevSecOps Automation · AWS · Infrastructure as Code · Python · boto3 · moto · JSON Reporting · Risk Analytics · CI/CD Ready

## Quickstart
```bash
git clone https://github.com/your-org/CloudFortress.git
cd CloudFortress
pip install -r requirements.txt
python -m cli.main
```


### Usage
0. **Create .env file:**
   ```.env
   PRODUCT_ID=
   PROJECT_ID=
   REPORT_URL
   ```
1. **Run with simulated AWS:**

   ```bash
   python -m cli.main
   ```
2. **Send report to dashboard:**

   ```bash
   python -m cli.main --send
   ```

The output file `scan_result.json` will be created in the project root.

## 📁 Project Structure

```
CloudFortress/
├── app/                  # Core logic and scanners
├── cli/                  # Entry points (main runner + report sender)
├── requirements.txt      # Python dependencies
├── scan_result.json      # Generated scan output (ignored by Git)
├── README.md             # Project overview
└── topics_overview.md    # Security concepts and phase breakdown
```
```
├── app
│   ├── __init__.py
│   ├── core
│   │   ├── __init__.py
│   │   └── aws_connector.py
│   ├── data
│   │   ├── __init__.py
│   │   └── sample_env.py
│   ├── interface
│   │   ├── __init__.py
│   │   └── json_interface.py
│   └── services
│       ├── __init__.py
│       ├── ec2_scanner.py
│       ├── iam_scanner.py
│       ├── s3_scanner.py
│       └── sg_scanner.py
```

