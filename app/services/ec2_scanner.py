import re
import boto3  # AWS SDK for Python to interact with AWS services.

def scan_ec2_instances():
    ec2 = boto3.client('ec2', region_name='us-west-1')
    findings = []

    instances = ec2.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            userdata = instance.get('UserData', '')

            # Search for secrets
            if 'password=' in userdata or 'AKIA' in userdata:
                findings.append({
                    "instance_id": instance_id,
                    "risk": "Secrets in user data",
                    "recommendation": "Remove credentials from EC2 user data"
                })

            # Check security groups
            for sg in instance['SecurityGroups']:
                if sg['GroupName'] == 'open-sg':
                    findings.append({
                        "instance_id": instance_id,
                        "risk": "Port 22 open to the world",
                        "recommendation": "Restrict SSH to known IPs"
                    })
    return findings
