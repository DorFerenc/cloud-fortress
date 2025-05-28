def scan_ec2_instances(ec2_client):
    """
    Scans EC2 instances for misconfigurations and embedded risks.

    Cyber Concepts Covered:
    -----------------------

    🔐 Secrets in EC2 User Data:
    ----------------------------
    - EC2 user data is accessible to any user with EC2 read privileges (and in some cases, accessible via SSRF).
    - Storing secrets like passwords, AWS access keys (e.g., AKIA...), or tokens in user data exposes your environment to full compromise.
    - These secrets can be harvested by attackers to escalate privileges or pivot laterally.

    🌍 Open Ports in Security Groups:
    ---------------------------------
    - EC2 security groups act like virtual firewalls.
    - Opening SSH (port 22) or other sensitive ports to the world (0.0.0.0/0) allows brute force or exploitation attempts by anyone on the internet.
    - This is a common Initial Access technique attackers exploit.

    🛰️ Metadata Service Exposure (IMDSv1):
    --------------------------------------
    - EC2 instances have a metadata API that can be queried locally
    - IMDSv1 doesn't require authentication. If a web app is vulnerable to SSRF, attackers can access metadata (including IAM role credentials).
    - IMDSv2 mitigates this by requiring a session token.
    - Keeping IMDSv1 enabled with `HttpTokens: optional` is a risk and should be corrected.

    Returns:
        A list of findings per instance, each containing:
        - instance_id, ip, name, type, memory
        - risk description, recommendation, severity (Low/Medium/High)
        - mitre_tactic, mitre_technique
    """
    findings = []

    reservations = ec2_client.describe_instances()['Reservations']
    for reservation in reservations:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            name = next((
                tag['Value'] for tag in instance.get('Tags', [])
                if tag['Key'] == 'Name'
            ), instance_id)

            # Metadata for report
            meta = {
                "instance_id": instance_id,
                "name": name,
                "category": "compute",
                "type": "EC2 instance"
            }

            # 1. Check for secrets in EC2 user data
            try:
                user_data_resp = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )
                user_data_b64 = user_data_resp.get('UserData', {}).get('Value')
                if user_data_b64:
                    import base64
                    user_data = base64.b64decode(user_data_b64).decode('utf-8', errors='ignore')
                    if 'password=' in user_data or 'AKIA' in user_data:
                        findings.append({
                            **meta,
                            "risk": "Secrets exposed in EC2 user data",
                            "recommendation": "Never store credentials in user data. Use IAM roles or AWS Secrets Manager.",
                            "severity": "High",
                            "mitre_tactic": "Defense Evasion",
                            "mitre_technique": "Expose Sensitive Data in User Data (T1552.001)"
                        })
            except Exception:
                pass  # User data inaccessible (possible permissions)

            # 2. Check security groups for open SSH
            for sg in instance['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_details = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                for rule in sg_details.get('IpPermissions', []):
                    from_ports = rule.get('FromPort')
                    ip_ranges = rule.get('IpRanges', [])
                    if from_ports == 22 and any(r.get('CidrIp') == '0.0.0.0/0' for r in ip_ranges):
                        findings.append({
                            **meta,
                            "risk": "SSH port (22) open to the world",
                            "recommendation": "Restrict SSH access to specific IP ranges (e.g., VPN or office IPs)",
                            "severity": "Medium",
                            "mitre_tactic": "Initial Access",
                            "mitre_technique": "Exploit Public-Facing Application (T1190)"
                        })

            # 3. Check for IMDSv1 (Metadata API v1)
            metadata_options = instance.get('MetadataOptions', {})
            if metadata_options.get('HttpTokens') == 'optional':
                findings.append({
                    **meta,
                    "risk": "IMDSv1 enabled (token not required)",
                    "recommendation": "Set HttpTokens=required to enforce IMDSv2 and block SSRF metadata leaks",
                    "severity": "Medium",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "Cloud Instance Metadata API (T1522)"
                })

    return findings
