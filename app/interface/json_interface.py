 # Creates output compatible with frontend
import json
from datetime import datetime
import uuid

def generate_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:6]}"

def generate_report(s3_findings, iam_findings, ec2_findings, sg_findings):
    def generate_id(prefix):
        return f"{prefix}-{uuid.uuid4().hex[:6]}"
    report = {
        "type": "cat",  # Added required field
        "agent_id": "agent-123451",  # Added required field
        "agent_name": "CNAPP-Agent1",  # Added required field
        "agent_ip": "192.168.1.101",  # Added required field
        # "agent_ip": "127.0.0.1",  # Added required field
        "projectID": "proj-cnapp-lite-001",
        "details": {
            "color": "blue",
            "type": "cloud",
            "name": "CNAPP-lite Scan",
            "team": "Student"
        },
        "assets": [],
        "meta-data": [],
        "alerts": []
    }

    asset_map = {}

    # ---------- S3 Findings ----------
    for s3_finding in s3_findings:
        asset_id = generate_id("ass")
        bucket_name = s3_finding["bucket_name"]

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "name": bucket_name,
            "memory": "N/A",
            "category": "storage",
            "type": "S3 Bucket"
        })

        asset_map[bucket_name] = asset_id

        # Add to meta-data with real S3 config
        report["meta-data"].extend([
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Encryption",
                "type": "S3 encryption",
                "desc": s3_finding.get("encryption", "Unknown")
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Versioning",
                "type": "S3 versioning",
                "desc": s3_finding.get("versioning", "Unknown")
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Logging",
                "type": "S3 logging",
                "desc": s3_finding.get("logging", "Unknown")
            }
        ])

        # Add alert if misconfigured
        if s3_finding["risk_level"] == "High":
            report["alerts"].append({
                "asset-id": asset_id,
                "ip": "N/A",
                "port": 443,
                "host": f"{bucket_name}.s3.amazonaws.com",
                "alert_name": s3_finding["misconfiguration_type"],
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Expose Storage to Internet (T1530)",
                "severity": 4,
                "time": datetime.utcnow().isoformat() + "Z"
            })


     # ---------- IAM Findings ----------
    for iam in iam_findings:
        asset_id = generate_id("ass")
        role_name = iam["role_name"]

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "name": role_name,
            "memory": "N/A",
            "category": "identity",
            "type": "IAM role"
        })

        report["alerts"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "port": 0,
            "host": role_name,
            "alert_name": iam["risk"],
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "Abuse of Overly Permissive Role (T1078)",
            "severity": 5,
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- EC2 Findings ----------
    for ec2 in ec2_findings:
        instance_id = ec2["instance_id"]
        asset_id = asset_map.get(instance_id, generate_id("ass"))

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "192.168.1.10",
            "name": instance_id,
            "memory": "4GB",
            "category": "compute",
            "type": "EC2 instance"
        })

        report["alerts"].append({
            "asset-id": asset_id,
            "ip": "192.168.1.10",
            "port": 0,
            "host": f"{instance_id}.aws.local",
            "alert_name": ec2["risk"],
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "Expose Sensitive Data in User Data (T1552)",
            "severity": 4,
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- SG Findings ----------
    for sg in sg_findings:
        asset_id = generate_id("ass")

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "name": sg["group_name"],
            "memory": "N/A",
            "category": "network",
            "type": "Security Group"
        })

        report["alerts"].append({
            "asset-id": asset_id,
            "ip": sg["cidr"],
            "port": sg["from_port"],
            "host": sg["group_name"],
            "alert_name": sg["risk"],
            "mitre_tactic": "Initial Access",
            "mitre_technique": "Exposed Service (T1133)",
            "severity": 5 if sg["from_port"] in [22, 3389] else 3,
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- Write JSON ----------
    with open("scan_result.json", "w") as file:
        json.dump(report, file, indent=4)

    print("[+] Report written to scan_result.json")


# import json
# from datetime import datetime
# import uuid

# def generate_report(s3_findings):
#     def generate_id(prefix):
#         return f"{prefix}-{uuid.uuid4().hex[:6]}"

#     report = {
#         "type": "cat",  # Added required field
#         "agent_id": "agent-12345",  # Added required field
#         "agent_name": "CNAPP-Agent",  # Added required field
#         "agent_ip": "192.168.1.100",  # Added required field
#         "productId": "prod-cnapp-lite",
#         "product-details": {
#             "color": "blue",
#             "type": "cybersecurity",
#             "name": "CNAPP-lite Scan",
#             "team": "Student"
#         },
#         "projectId": "proj-aws-lab",
#         "project-details": {
#             "name": "AWS Corp",
#             "desc": "corporate environment"
#         },
#         "assets": [],
#         "meta-data": [],
#         "alerts": []
#     }

#     for finding in s3_findings:
#         asset_id = generate_id("ass")
#         bucket_name = finding["bucket_name"]

#         # Add to assets
#         report["assets"].append({
#             "asset-id": asset_id,
#             "ip": "N/A",
#             "name": bucket_name,
#             "memory": "N/A",
#             "category": "storage",
#             "type": "S3 bucket"
#         })

#         # Add to meta-data (placeholder entry for now)
#         report["meta-data"].append({
#             "asset-id": asset_id,
#             "meta-id": generate_id("meta"),
#             "meta-name": f"{bucket_name} ACL",
#             "type": "ACL",
#             "desc": "Access control configuration of the bucket"
#         })

#         # Add alert if misconfigured
#         if finding["risk_level"] == "High":
#             report["alerts"].append({
#                 "asset-id": asset_id,
#                 "ip": "N/A",
#                 "port": 443,
#                 "host": f"{bucket_name}.s3.amazonaws.com",
#                 "alert_name": finding["misconfiguration_type"],
#                 "mitre_tactic": "Initial Access",
#                 "mitre_technique": "Expose Storage to Internet (T1530)",
#                 "severity": 4,
#                 "time": datetime.utcnow().isoformat() + "Z"
#             })

#     with open("scan_result.json", "w") as f:
#         json.dump(report, f, indent=4)

#     print("[+] Report written to scan_result.json (updated schema)")
