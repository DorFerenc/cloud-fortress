"""
aws_build_scenario.py

This script programmatically builds a demo AWS environment for security testing and training.

After running this script, your AWS environment will contain:

1. **Three S3 Buckets:**
   - `cf-demo-secure-<suffix>`: Private, no issues.
   - `cf-demo-public-<suffix>`: Public Read, high-risk.
   - `cf-demo-midrisk-<suffix>`: Private but unencrypted & no versioning (medium-risk).

2. **One IAM Role:**
   - `CFTestRole`: EC2-assumable with wildcard policy (high-risk).

3. **One IAM Instance Profile:**
   - `CFTestProfile`: Links `CFTestRole` for EC2 usage.

4. **Three Security Groups:**
   - `cf-open-sg`: SSH (22) open to 0.0.0.0/0 (medium/high-risk).
   - `cf-open-all-sg`: All ports (0-65535) open to 0.0.0.0/0 (high-risk).
   - `cf-https-sg`: HTTPS (443) restricted to a sample CIDR (good practice).

5. **Three EC2 Instances:**
   - `i-<insecure>`: Uses `CFTestProfile`, insecure user-data, attached to `cf-open-sg` (high-risk).
   - `i-<clean>`: No role, no user-data, attached to `cf-https-sg` (low-risk).
   - `i-<allports>`: Uses `CFTestProfile`, no user-data, attached to `cf-open-all-sg` (medium-risk).

**Warning:**
Do NOT run this in production. Resources are insecure for demonstration purposes only.
"""

import json
import os
import uuid
import time
from botocore.exceptions import ClientError


def build_demo_resources(clients):
    s3  = clients["s3"]
    iam = clients["iam"]
    ec2 = clients["ec2"]
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def unique_name(base):
        return f"{base}-{uuid.uuid4().hex[:6]}"

    # --- S3 Buckets ---
    bucket_specs = [
        ("cf-demo-secure",   False),  # safe
        ("cf-demo-public",    True),  # high-risk
        ("cf-demo-midrisk",  False),  # medium-risk
    ]
    for base, is_public in bucket_specs:
        name = unique_name(base)
        try:
            params = {"Bucket": name}
            if region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**params)
            print(f"[+] S3 bucket {name} created")
        except ClientError as e:
            code = e.response['Error']['Code']
            print(f"[!] S3 {name} creation skipped: {code}")
            continue
        # medium-risk: do nothing (private, no encryption/versioning)
        if base == "cf-demo-midrisk":
            print(f"[*] {name} is medium-risk (no encryption/versioning)")
        if is_public:
            try:
                s3.put_bucket_acl(Bucket=name, ACL="public-read")
                print(f"[+] Public ACL set on {name}")
            except ClientError:
                try:
                    policy = {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["s3:GetObject"],
                            "Resource": [f"arn:aws:s3:::{name}/*"]
                        }]
                    }
                    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
                    print(f"[+] Public bucket policy on {name}")
                except ClientError as e2:
                    print(f"[!] Policy fallback failed for {name}: {e2.response['Error']['Message']}")

    # --- IAM Role & Instance Profile ---
    trust = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    for action in ["create_role","put_role_policy"]:
        try:
            if action == "create_role":
                iam.create_role(RoleName="CFTestRole", AssumeRolePolicyDocument=json.dumps(trust))
                print("[+] IAM role CFTestRole created")
            else:
                iam.put_role_policy(RoleName="CFTestRole", PolicyName="CFTestPolicy", PolicyDocument=json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}))
                print("[+] IAM wildcard policy attached to CFTestRole")
        except ClientError as e:
            code = e.response['Error']['Code']
            print(f"[!] IAM {action} skipped: {code}")
    try:
        iam.create_instance_profile(InstanceProfileName="CFTestProfile")
        iam.add_role_to_instance_profile(InstanceProfileName="CFTestProfile", RoleName="CFTestRole")
        print("[+] Instance profile CFTestProfile created & role attached")
    except ClientError as e:
        print(f"[!] Instance profile setup skipped: {e.response['Error']['Code']}")

    # --- Security Groups ---
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg_defs = [
        ("cf-open-sg",     [("tcp",22)],   True),    # SSH only
        ("cf-open-all-sg", [("tcp",0,65535)], True),  # all ports
        ("cf-https-sg",    [("tcp",443,"203.0.113.0/24")], False), # https limited
    ]
    sg_ids = {}
    for name_base, rules, _ in sg_defs:
        try:
            sg = ec2.create_security_group(GroupName=name_base, Description="Demo SG", VpcId=vpc_id)
            sg_id = sg["GroupId"]
            print(f"[+] SG {name_base} created")
        except ClientError as e:
            if e.response['Error']['Code'] == "InvalidGroup.Duplicate":
                sg_id = ec2.describe_security_groups(Filters=[{"Name":"group-name","Values":[name_base]}])["SecurityGroups"][0]["GroupId"]
                print(f"[!] SG {name_base} exists, reused {sg_id}")
            else:
                print(f"[!] SG creation error for {name_base}: {e}")
                continue
        sg_ids[name_base] = sg_id
        for rule in rules:
            proto, fr = rule[0], rule[1]
            to = rule[2] if len(rule) == 3 else fr
            cidr = rule[2] if len(rule) == 3 else "0.0.0.0/0"
            try:
                ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{"IpProtocol":proto,"FromPort":fr,"ToPort":to,"IpRanges":[{"CidrIp":cidr}]}])
                print(f"[+] Rule {proto} {fr}-{to} {cidr} on {name_base}")
            except ClientError as e:
                print(f"[!] Rule skipped for {name_base}: {e.response['Error']['Message']}")

    # --- EC2 Instances ---
    images = ec2.describe_images(Filters=[{"Name":"name","Values":["amzn2-ami-hvm-2.0.*-x86_64-gp2"]}])["Images"]
    ami = sorted(images, key=lambda x: x["CreationDate"])[-1]["ImageId"]

    # 1) Insecure
    try:
        inst1 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro", IamInstanceProfile={"Name":"CFTestProfile"}, UserData="password=badpass123", SecurityGroupIds=[sg_ids["cf-open-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        print(f"[+] Insecure EC2 {inst1} launched")
        ec2.stop_instances(InstanceIds=[inst1])
    except ClientError as e:
        print(f"[!] Insecure EC2 error: {e}")

    # 2) Clean
    try:
        inst2 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro", SecurityGroupIds=[sg_ids["cf-https-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        print(f"[+] Clean EC2 {inst2} launched")
        ec2.stop_instances(InstanceIds=[inst2])
    except ClientError as e:
        print(f"[!] Clean EC2 error: {e}")

    # 3) Mid-risk
    try:
        inst3 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro", IamInstanceProfile={"Name":"CFTestProfile"}, SecurityGroupIds=[sg_ids["cf-open-all-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        print(f"[+] Mid-risk EC2 {inst3} launched")
        ec2.stop_instances(InstanceIds=[inst3])
    except ClientError as e:
        print(f"[!] Mid-risk EC2 error: {e}")

    print("[*] Demo resource build complete.")
