def scan_security_groups(ec2_client):
    """
    Scans AWS security groups for dangerous or overly permissive configurations.

    Checks:
    - Publicly exposed ports (ingress from 0.0.0.0/0)
    - Open egress to the world
    - Wide port ranges (e.g., 0-65535)
    - Dangerous exposed ports (e.g., 3306, 6379)
    - Duplicated risky rules across groups (pattern detection)

    Returns:
        List of findings with details and MITRE context.
    """
    findings = []
    risky_ports = [22, 3389, 3306, 5432, 6379, 9200]
    rule_hash_map = {}  # group_id → rule hash

    security_groups = ec2_client.describe_security_groups()['SecurityGroups']

    for sg in security_groups:
        group_id = sg['GroupId']
        group_name = sg.get('GroupName', 'Unnamed')
        rules = sg.get('IpPermissions', [])
        egress = sg.get('IpPermissionsEgress', [])

        rule_hash = hash(f"{rules}{egress}")

        meta = {
            "group_id": group_id,
            "group_name": group_name,
        }

        # Track group-wide risk summary
        group_findings = []

        # Ingress rules
        for rule in rules:
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_ranges = rule.get('IpRanges', [])

            for ip in ip_ranges:
                cidr = ip.get('CidrIp', '')

                # 1. Publicly exposed port
                if cidr == '0.0.0.0/0' and from_port is not None:
                    port_range = f"{from_port}-{to_port}" if from_port != to_port else f"{from_port}"

                    severity = (
                        "High" if from_port in [22, 3389]
                        else "Medium" if from_port in risky_ports
                        else "Low"
                    )

                    group_findings.append({
                        **meta,
                        "port_range": port_range,
                        "cidr": cidr,
                        "risk": f"Port {port_range} open to the world",
                        "recommendation": "Restrict access to known IPs",
                        "severity": severity,
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "Exploit Public-Facing Application (T1190)"
                    })

                # 2. Dangerous port exposed
                if from_port in risky_ports and cidr == '0.0.0.0/0':
                    group_findings.append({
                        **meta,
                        "port_range": str(from_port),
                        "cidr": cidr,
                        "risk": f"Dangerous port {from_port} exposed to the world",
                        "recommendation": f"Restrict this port to internal networks only",
                        "severity": "High",
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "Exploit Public-Facing Application (T1190)"
                    })

                # 3. Wide port range
                if from_port == 0 and to_port == 65535 and cidr == '0.0.0.0/0':
                    group_findings.append({
                        **meta,
                        "port_range": "0-65535",
                        "cidr": cidr,
                        "risk": "All ports open to the world",
                        "recommendation": "Limit to specific ports and known IPs",
                        "severity": "High",
                        "mitre_tactic": "Initial Access",
                        "mitre_technique": "Exploit Public-Facing Application (T1190)"
                    })

        # Egress rules
        for rule in egress:
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            ip_ranges = rule.get('IpRanges', [])
            for ip in ip_ranges:
                cidr = ip.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    group_findings.append({
                        **meta,
                        "port_range": f"{from_port}-{to_port}",
                        "cidr": cidr,
                        "risk": "Unrestricted outbound traffic (egress to 0.0.0.0/0)",
                        "recommendation": "Restrict egress to only required services",
                        "severity": "Medium",
                        "mitre_tactic": "Exfiltration",
                        "mitre_technique": "Exfiltration Over C2 Channel (T1041)"
                    })

        # Check for duplicates and adjust last finding
        if rule_hash in rule_hash_map:
            for finding in group_findings:
                finding["risk"] += " (duplicate rule detected)"
                finding["recommendation"] += " Review SGs for duplicated rules."
                finding["severity"] = upgrade_severity(finding["severity"])
        else:
            rule_hash_map[rule_hash] = group_id

        findings.extend(group_findings)

    return findings


def upgrade_severity(current):
    """
    Upgrade severity one level: Low → Medium → High
    """
    order = {"Low": "Medium", "Medium": "High", "High": "High"}
    return order.get(current, "High")
