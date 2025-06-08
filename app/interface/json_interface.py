# Creates output compatible with frontend
import json
from datetime import datetime

def build_asset(asset_id, name, category, type_, ip="N/A", memory="N/A"):
    return {
        "asset-id": asset_id,
        "ip": ip,
        "name": name,
        "memory": memory,
        "category": category,
        "type": type_
    }

def build_meta(asset_id, meta_name, meta_type, desc):
    return {
        "asset-id": asset_id,
        "meta-id": f"META-{meta_name}-{asset_id}",
        "meta-name": meta_name,
        "type": meta_type,
        "desc": desc
    }

def build_alert(asset_id, ip, port, host, alert_name, mitre_tactic, mitre_technique, severity, time):
    return {
        "asset-id": asset_id,
        "ip": ip,
        "port": port,
        "host": host,
        "alert_name": alert_name,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "severity": severity,
        "time": time
    }

def process_s3_findings(s3_findings, username="Unknown"):
    assets, meta_data, alerts = [], [], []
    for s3_finding in s3_findings:
        bucket_name = s3_finding["bucket_name"]
        asset_id = f"S3asset-{bucket_name}"
        assets.append(build_asset(asset_id, bucket_name, "storage", "S3 Bucket"))

        meta_data.append(build_meta(asset_id, "User", "User", username))
        meta_data.append(build_meta(asset_id, "Risk Level", "Risk Assessment", s3_finding.get("severity", "Unknown")))
        meta_data.append(build_meta(asset_id, "Recommendation", "Recommendation", s3_finding.get("recommendation", "No recommendation available.")))

        alerts.append(build_alert(
            asset_id=asset_id,
            ip=f"{s3_finding.get('ip', 'N/A')} Recommendation: {s3_finding.get('recommendation', 'No recommendation available.')}",
            port=s3_finding.get("port", 443),
            host=s3_finding.get("host", f"{bucket_name}.s3.amazonaws.com"),
            alert_name=s3_finding["misconfiguration_type"],
            mitre_tactic=s3_finding.get("mitre_tactic", "Unknown"),
            mitre_technique=s3_finding.get("mitre_technique", "Unknown"),
            severity=s3_finding.get("severity"),
            time=datetime.utcnow().isoformat()
        ))
    return assets, meta_data, alerts

def process_iam_findings(iam_findings, username="Unknown"):
    assets, meta_data, alerts = [], [], []
    for iam in iam_findings:
        role_name = iam["role_name"]
        asset_id = f"IAMasset-{role_name}"
        assets.append(build_asset(asset_id, role_name, "identity", "IAM role"))

        meta_data.append(build_meta(asset_id, "User", "User", username))
        meta_data.append(build_meta(asset_id, "Risk Level", "Risk Assessment", iam.get("severity", "Unknown")))
        meta_data.append(build_meta(asset_id, "Recommendation", "Recommendation", iam.get("recommendation", "No recommendation available.")))

        alerts.append(build_alert(
            asset_id=asset_id,
            ip= f"N/A Recommendation: {iam.get('recommendation', 'No recommendation available.')}",
            port=0,
            host=role_name,
            alert_name=iam["risk"],
            mitre_tactic=iam["mitre_tactic"],
            mitre_technique=iam["mitre_technique"],
            severity=iam["severity"],
            time=datetime.utcnow().isoformat()
        ))
    return assets, meta_data, alerts

def process_ec2_findings(ec2_findings, username="Unknown"):
    assets, meta_data, alerts = [], [], []
    for ec2 in ec2_findings:
        instance_id = ec2["instance_id"]
        asset_id = f"EC2asset-{instance_id}"
        assets.append(build_asset(asset_id, ec2["name"], "compute", ec2["type"]))

        meta_data.append(build_meta(asset_id, "User", "User", username))
        meta_data.append(build_meta(asset_id, "Risk Level", "Risk Assessment", ec2.get("severity", "Unknown")))
        meta_data.append(build_meta(asset_id, "Recommendation", "Recommendation", ec2.get("recommendation", "No recommendation available.")))

        alerts.append(build_alert(
            asset_id=asset_id,
            ip="N/A Recommendation: " + ec2.get("recommendation", "No recommendation available."),
            port=0,
            host=f"{ec2['name']}.aws.local",
            alert_name=ec2["risk"],
            mitre_tactic=ec2["mitre_tactic"],
            mitre_technique=ec2["mitre_technique"],
            severity=ec2["severity"],
            time=datetime.utcnow().isoformat()
        ))
    return assets, meta_data, alerts

def process_sg_findings(sg_findings, username="Unknown"):
    assets, meta_data, alerts = [], [], []
    for sg in sg_findings:
        group_name = sg.get("group_name", "Unnamed")
        asset_id = f"SGasset-{group_name}"
        assets.append(build_asset(asset_id, group_name, "network", "Security Group"))

        meta_data.append(build_meta(asset_id, "User", "User", username))
        meta_data.append(build_meta(asset_id, "Risk Level", "Risk Assessment", sg.get("severity", "Unknown")))
        meta_data.append(build_meta(asset_id, "Recommendation", "Recommendation", sg.get("recommendation", "No recommendation available.")))


        port_range = sg.get("port_range", "0")
        port = int(port_range.split("-")[0]) if "-" in port_range else int(port_range)
        alerts.append(build_alert(
            asset_id=asset_id,
            ip=sg.get("cidr", "N/A"),
            port=port,
            host=group_name,
            alert_name=sg["risk"],
            mitre_tactic=sg.get("mitre_tactic", "Defense Evasion"),
            mitre_technique=sg.get("mitre_technique", "Uncategorized Security Group Misconfiguration"),
            severity=sg.get("severity", "Medium"),
            time=datetime.utcnow().isoformat()
        ))
    return assets, meta_data, alerts

def generate_report(s3_findings, iam_findings, ec2_findings, sg_findings, username, PRODUCT_ID, PROJECT_ID):
    """
    Build a structured report for the frontend from findings.
    """
    report = {
        "productId": PRODUCT_ID,
        "product_details": {
            "color": "blueish",
            "type": "CNAPP lite",
            "name": f"report for user {username}",
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

    # S3
    s3_assets, s3_meta, s3_alerts = process_s3_findings(s3_findings, username)
    report["assets"].extend(s3_assets)
    report["meta-data"].extend(s3_meta)
    report["alerts"].extend(s3_alerts)

    # IAM
    iam_assets, iam_meta, iam_alerts = process_iam_findings(iam_findings, username)
    report["assets"].extend(iam_assets)
    report["meta-data"].extend(iam_meta)
    report["alerts"].extend(iam_alerts)

    # EC2
    ec2_assets, ec2_meta, ec2_alerts = process_ec2_findings(ec2_findings, username)
    report["assets"].extend(ec2_assets)
    report["meta-data"].extend(ec2_meta)
    report["alerts"].extend(ec2_alerts)

    # SG
    sg_assets, sg_meta, sg_alerts = process_sg_findings(sg_findings, username)
    report["assets"].extend(sg_assets)
    report["meta-data"].extend(sg_meta)
    report["alerts"].extend(sg_alerts)

    return report
    # with open(file_path, "w") as file:
    #     json.dump(report, file, indent=4)

    # print(f"[+] Report written to {file_path}")
    # return json.dumps(report, indent=4)
