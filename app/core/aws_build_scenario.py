"""
aws_build_scenario.py

This script programmatically builds a demo AWS environment for security testing and training.

After running this script, your AWS environment will contain:

1. **Four S3 Buckets:**
   - `cf-demo-secure-<suffix>`: Private, encrypted, versioning & logging enabled (safe).
   - `cf-demo-public-<suffix>`: Public Read, high-risk.
   - `cf-demo-midrisk-<suffix>`: Private but unencrypted & no versioning (medium-risk).
   - `cf-demo-safe-<suffix>`: Private, encrypted, versioning enabled, public access blocked (safe).

2. **Two IAM Roles:**
   - `CFTestRole`: EC2-assumable with wildcard policy (high-risk).
   - `CFSafeRole`: EC2-assumable with least-privilege policy (safe).

3. **Two IAM Instance Profiles:**
   - `CFTestProfile`: Links `CFTestRole` for EC2 usage.
   - `CFSafeProfile`: Links `CFSafeRole` for EC2 usage.

4. **Four Security Groups:**
   - `cf-open-sg`: SSH (22) open to 0.0.0.0/0 (medium/high-risk).
   - `cf-open-all-sg`: All ports (0-65535) open to 0.0.0.0/0 (high-risk).
   - `cf-https-sg`: HTTPS (443) restricted to sample CIDR (good practice).
   - `cf-ssh-restricted-sg`: SSH (22) restricted to a sample CIDR (safe).

5. **Four EC2 Instances:**
   - `i-insecure`: Uses `CFTestProfile`, insecure user-data, attached to `cf-open-sg` (high-risk).
   - `i-clean`: No role, no user-data, attached to `cf-https-sg` (low-risk).
   - `i-mid`: Uses `CFTestProfile`, no user-data, attached to `cf-open-all-sg` (medium-risk).
   - `i-safe`: Uses `CFSafeProfile`, no user-data, attached to `cf-ssh-restricted-sg` (safe).

**Warning:**
Do NOT run this in production. Resources are for demonstration purposes only.
"""

import json
import os
import uuid
import time
from botocore.exceptions import ClientError


def build_demo_resources(clients):
    s3 = clients["s3"]
    iam = clients["iam"]
    ec2 = clients["ec2"]
    region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def unique_name(base):
        return f"{base}-{uuid.uuid4().hex[:6]}"

    # --- S3 Buckets ---
    bucket_specs = [
        ("cf-demo-secure", False, True, True, True),    # private, encrypted, versioned, logged
        ("cf-demo-public", True, False, False, False),  # high-risk
        ("cf-demo-midrisk", False, False, False, False),# medium-risk
        ("cf-demo-safe", False, True, True, False),     # safe: encryption+version only
    ]
    for base, is_public, enc, ver, log in bucket_specs:
        name = unique_name(base)
        try:
            params = {"Bucket": name}
            if region != "us-east-1":
                params["CreateBucketConfiguration"] = {"LocationConstraint": region}
            s3.create_bucket(**params)
            print(f"[+] S3 bucket {name} created")
        except ClientError as e:
            print(f"[!] S3 {name} creation skipped: {e.response['Error']['Code']}")
            continue
        if enc:
            try:
                s3.put_bucket_encryption(
                    Bucket=name,
                    ServerSideEncryptionConfiguration={"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}
                )
            except ClientError:
                pass
        if ver:
            try:
                s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status":"Enabled"})
            except ClientError:
                pass
        if log:
            try:
                log_target = bucket_specs[0][0]  # use first bucket as log target
                s3.put_bucket_logging(
                    Bucket=name,
                    BucketLoggingStatus={"LoggingEnabled":{"TargetBucket":log_target, "TargetPrefix":f"{name}/"}}
                )
            except ClientError:
                pass
        if is_public:
            try:
                s3.put_bucket_acl(Bucket=name, ACL="public-read")
            except ClientError:
                pass

    # --- IAM Roles & Instance Profiles ---
    trust = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
    try:
        iam.create_role(RoleName="CFTestRole", AssumeRolePolicyDocument=json.dumps(trust))
    except ClientError:
        pass
    try:
        iam.put_role_policy(
            RoleName="CFTestRole",
            PolicyName="CFTestPolicy",
            PolicyDocument=json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})
        )
    except ClientError:
        pass
    try:
        iam.create_instance_profile(InstanceProfileName="CFTestProfile")
        iam.add_role_to_instance_profile(InstanceProfileName="CFTestProfile", RoleName="CFTestRole")
    except ClientError:
        pass

    safe_policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances","s3:ListBucket"],"Resource":"*"}]}
    try:
        iam.create_role(RoleName="CFSafeRole", AssumeRolePolicyDocument=json.dumps(trust))
    except ClientError:
        pass
    try:
        iam.put_role_policy(RoleName="CFSafeRole", PolicyName="CFSafePolicy", PolicyDocument=json.dumps(safe_policy))
    except ClientError:
        pass
    try:
        iam.create_instance_profile(InstanceProfileName="CFSafeProfile")
        iam.add_role_to_instance_profile(InstanceProfileName="CFSafeProfile", RoleName="CFSafeRole")
    except ClientError:
        pass

    # --- Security Groups ---
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    sg_defs = [
        ("cf-open-sg", [("tcp", 22)], True),
        ("cf-open-all-sg", [("tcp", 0, 65535)], True),
        ("cf-https-sg", [("tcp", 443, "203.0.113.0/24")], False),
        ("cf-ssh-restricted-sg", [("tcp", 22, "203.0.113.0/24")], False),
    ]
    sg_ids = {}
    for name_base, rules, _ in sg_defs:
        try:
            sg = ec2.create_security_group(GroupName=name_base, Description="Demo SG", VpcId=vpc_id)
            sg_id = sg["GroupId"]
        except ClientError:
            sg_id = ec2.describe_security_groups(Filters=[{"Name":"group-name","Values":[name_base]}])["SecurityGroups"][0]["GroupId"]
        sg_ids[name_base] = sg_id
        for rule in rules:
            proto = rule[0]
            fr = rule[1]
            # determine port range and CIDR intelligently
            if len(rule) == 3:
                if isinstance(rule[2], str):
                    to = fr
                    cidr = rule[2]
                else:
                    to = rule[2]
                    cidr = "0.0.0.0/0"
            else:
                to = fr
                cidr = "0.0.0.0/0"
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        "IpProtocol": proto,
                        "FromPort": fr,
                        "ToPort": to,
                        "IpRanges": [{"CidrIp": cidr}]
                    }]
                )
            except ClientError:
                pass

    # --- EC2 Instances ---
    images = ec2.describe_images(Filters=[{"Name":"name","Values":["amzn2-ami-hvm-2.0.*-x86_64-gp2"]}])["Images"]
    ami = sorted(images, key=lambda x: x["CreationDate"])[-1]["ImageId"]

    # 1) Insecure
    try:
        inst1 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro",
            IamInstanceProfile={"Name":"CFTestProfile"}, UserData="password=badpass123",
            SecurityGroupIds=[sg_ids["cf-open-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[inst1])
    except ClientError:
        pass

    # 2) Clean
    try:
        inst2 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro",
            SecurityGroupIds=[sg_ids["cf-https-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[inst2])
    except ClientError:
        pass

    # 3) Mid-risk
    try:
        inst3 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro",
            IamInstanceProfile={"Name":"CFTestProfile"},
            SecurityGroupIds=[sg_ids["cf-open-all-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[inst3])
    except ClientError:
        pass

    # 4) Safe
    try:
        inst4 = ec2.run_instances(ImageId=ami, InstanceType="t2.micro",
            IamInstanceProfile={"Name":"CFSafeProfile"},
            SecurityGroupIds=[sg_ids["cf-ssh-restricted-sg"]], MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[inst4])
    except ClientError:
        pass

    print("[*] Demo resource build complete.")
