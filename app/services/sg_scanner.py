import boto3 # AWS SDK for Python to interact with AWS services.

def scan_security_groups():
    ec2 = boto3.client('ec2', region_name='us-west-1')
    findings = []

    groups = ec2.describe_security_groups()['SecurityGroups']

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
