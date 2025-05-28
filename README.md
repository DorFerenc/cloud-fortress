# CloudFortress: Cloud Security Automation

CloudFortress is a Python-based CNAPP-lite scanner engineered for DevSecOps teams, security engineers, and cloud architects to **automate detection**, **visualize risk**, and **accelerate remediation** in AWS environments.

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

