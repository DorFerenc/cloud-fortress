 # Creates output compatible with frontend
import json
from datetime import datetime
import uuid

def generate_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:6]}"

def generate_report(s3_findings, iam_findings, ec2_findings, sg_findings, PRODUCT_ID, PROJECT_ID):
    report = {
        "productId": PRODUCT_ID,
        "product_details": {
            "color": "blueish",
            "type": "CNAPP lite",
            "name": "Blue Team Initiative",
            "team": "Delta"
        },
        "projectId": PROJECT_ID,
        "project_details": {
            "name": "Cloud Fortress",
            "desc": "corporate environment"
        },
        "assets": [],
        "meta-data": [],
        "alerts": []
    }

    asset_map = {}

    # ---------- S3 Findings ----------
    for s3_finding in s3_findings:
        asset_id = generate_id("s3_asset")
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
            },
             {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Public Access ACL",
                "type": "S3 access control",
                "desc": "Public" if s3_finding.get("public_acl") else "Private"
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Public Policy",
                "type": "S3 bucket policy",
                "desc": "Public" if s3_finding.get("public_policy") else "Private"
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Policy Summary",
                "type": "S3 bucket policy",
                "desc": s3_finding.get("bucket_policy", "None")
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Risk Level",
                "type": "Risk Assessment",
                "desc": s3_finding.get("risk_level", "Unknown")
            },
            {
                "asset-id": asset_id,
                "meta-id": generate_id("meta"),
                "meta-name": "Recommendation",
                "type": "Remediation",
                "desc": s3_finding.get("recommendation", "No recommendation available.")
            }
        ])


        # Add alert if risk is Medium or High
        report["alerts"].append({
            "asset-id": asset_id,
            "ip": f"{s3_finding.get('ip', 'N/A')} Recommendation: {s3_finding.get('recommendation', 'No recommendation available.')}",
            "port": s3_finding.get("port", 443),
            "host": s3_finding.get("host", f"{bucket_name}.s3.amazonaws.com"),
            "alert_name": s3_finding["misconfiguration_type"],
            "mitre_tactic": s3_finding.get("mitre_tactic", "Unknown"),
            "mitre_technique": s3_finding.get("mitre_technique", "Unknown"),
            "severity": s3_finding.get("severity"),
            "time": datetime.utcnow().isoformat() + "Z"
        })



     # ---------- IAM Findings ----------
    for iam in iam_findings:
        asset_id = generate_id("iam_asset")
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
            "ip": f"N/A Recommendation: {s3_finding.get('recommendation', 'No recommendation available.')}",
            "port": 0,
            "host": role_name,
            "alert_name": iam["risk"],
            "mitre_tactic": iam["mitre_tactic"],
            "mitre_technique": iam["mitre_technique"],
            "severity": iam["severity"],
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- EC2 Findings ----------
    for ec2 in ec2_findings:
        instance_id = ec2["instance_id"]
        asset_id = asset_map.get(instance_id, generate_id("ec2_asset"))

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "name": ec2["name"],
            "memory": "N/A",
            "category": "compute",
            "type": ec2["type"]
        })

        report["alerts"].append({
            "asset-id": asset_id,
            "ip": "N/A Recommendation: " + ec2.get("recommendation", "No recommendation available."),
            "port": 0,
            "host": f"{ec2['name']}.aws.local",
            "alert_name": ec2["risk"],
            "mitre_tactic": ec2["mitre_tactic"],
            "mitre_technique": ec2["mitre_technique"],
            "severity":ec2["severity"],
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- SG Findings ----------
    for sg in sg_findings:
        asset_id = generate_id("sg_asset")

        report["assets"].append({
            "asset-id": asset_id,
            "ip": "N/A",
            "name": sg.get("group_name", "Unnamed"),
            "memory": "N/A",
            "category": "network",
            "type": "Security Group"
        })

        report["alerts"].append({
            "asset-id": asset_id,
            "ip": sg.get("cidr", "N/A"),
            "port": int(sg.get("port_range", "0").split("-")[0]) if "-" in sg.get("port_range", "") else int(sg.get("port_range", 0)),
            "host": sg.get("group_name", "Unnamed"),
            "alert_name": sg["risk"],
            "mitre_tactic": sg.get("mitre_tactic", "Defense Evasion"),
            "mitre_technique": sg.get("mitre_technique", "Uncategorized Security Group Misconfiguration"),
            "severity": sg.get("severity", "Medium"),
            "time": datetime.utcnow().isoformat() + "Z"
        })

    # ---------- Write JSON ----------
    with open("scan_result.json", "w") as file:
        json.dump(report, file, indent=4)

    print("[+] Report written to scan_result.json")
    return json.dumps(report, indent=4)
