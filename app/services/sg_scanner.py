def scan_security_groups(get_ec2_client):
    findings = []

    groups = get_ec2_client.describe_security_groups()['SecurityGroups']

    for sg in groups:
        group_id = sg['GroupId']
        group_name = sg.get('GroupName', 'Unnamed')
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_ranges = rule.get('IpRanges', [])

            for ip in ip_ranges:
                cidr = ip.get('CidrIp', '')
                if cidr == '0.0.0.0/0' and from_port is not None:
                    findings.append({
                        "group_id": group_id,
                        "group_name": group_name,
                        "from_port": from_port,
                        "to_port": to_port,
                        "cidr": cidr,
                        "risk": f"Port {from_port}-{to_port} open to the world",
                        "recommendation": "Restrict access to known IP ranges"
                    })

    return findings
