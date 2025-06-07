"""
aws_build_scenario.py

This script programmatically builds a demo AWS environment for security testing and training.

After running this script, your AWS (or mock) environment will contain:

1. **Two S3 Buckets:**
   - `cf-demo-secure-<suffix>`: A private S3 bucket.
   - `cf-demo-public-<suffix>`: A public S3 bucket (ACL set to public-read or policy).

2. **One IAM Role:**
   - `CFTestRole`: An EC2-assumable IAM role with a wildcard policy (`Action: "*", Resource: "*"`).

3. **One IAM Instance Profile:**
   - `CFTestProfile`: Contains `CFTestRole` for EC2 use.

4. **One Security Group:**
   - `cf-open-sg`: Opens SSH (port 22) to `0.0.0.0/0` in your default VPC.

5. **One EC2 Instance:**
   - A `t2.micro` instance (stopped) using the latest Amazon Linux 2 AMI, with:
     - The `CFTestRole` attached via `CFTestProfile`.
     - User data containing `password=badpass123`.

**Warning:**
Do NOT run in production. Resources are intentionally insecure for learning and testing.
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

    # 1) S3 Buckets
    buckets = [
        (unique_name("cf-demo-secure"), False),
        (unique_name("cf-demo-public"), True),
    ]
    for name, is_public in buckets:
        try:
            if region == "us-east-1":
                s3.create_bucket(Bucket=name)
            else:
                s3.create_bucket(
                    Bucket=name,
                    CreateBucketConfiguration={"LocationConstraint": region}
                )
            print(f"[+] S3 bucket {name} created")
        except ClientError as e:
            code = e.response['Error']['Code']
            print(f"[!] S3 {name} creation skipped: {code}")
            continue
        if is_public:
            try:
                # Try ACL first
                s3.put_bucket_acl(Bucket=name, ACL="public-read")
                print(f"[+] Public ACL set on {name}")
            except ClientError as e:
                print(f"[!] Skipping ACL for {name}: {e.response['Error']['Message']}")
                try:
                    # Fallback to bucket policy
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
                    print(f"[+] Public bucket policy applied on {name}")
                except ClientError as e2:
                    print(f"[!] Policy fallback failed for {name}: {e2.response['Error']['Message']}")

    # 2) IAM Role + Inline Wildcard Policy
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }
    try:
        iam.create_role(
            RoleName="CFTestRole",
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        print("[+] IAM role CFTestRole created")
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print("[!] IAM role CFTestRole already exists, skipping creation")
        else:
            print(f"[!] IAM role creation error: {e}")
    try:
        iam.put_role_policy(
            RoleName="CFTestRole",
            PolicyName="CFTestPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]
            })
        )
        print("[+] IAM wildcard policy attached to CFTestRole")
    except ClientError as e:
        print(f"[!] IAM policy attachment error: {e}")

    # 3) IAM Instance Profile
    try:
        iam.create_instance_profile(InstanceProfileName="CFTestProfile")
        print("[+] Instance profile CFTestProfile created")
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print("[!] Instance profile CFTestProfile already exists, skipping")
        else:
            print(f"[!] Instance profile creation error: {e}")
    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName="CFTestProfile",
            RoleName="CFTestRole"
        )
        print("[+] CFTestRole added to CFTestProfile")
    except ClientError as e:
        if e.response['Error']['Code'] == 'LimitExceeded':
            print("[!] Role already in CFTestProfile, skipping")
        else:
            print(f"[!] Adding role to profile error: {e}")

    # 4) Security Group (open SSH)
    try:
        vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        sg = ec2.create_security_group(
            GroupName="cf-open-sg",
            Description="Demo open SG",
            VpcId=vpc_id
        )
        sg_id = sg["GroupId"]
        print(f"[+] Security Group cf-open-sg created in VPC {vpc_id}")
    except ClientError as e:
        if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
            sg_id = ec2.describe_security_groups(
                Filters=[{"Name":"group-name","Values":["cf-open-sg"]}]
            )['SecurityGroups'][0]['GroupId']
            print("[!] cf-open-sg already exists, using existing GroupId")
        else:
            print(f"[!] SG creation error: {e}")
            sg_id = None
    if sg_id:
        try:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }]
            )
            print(f"[+] SSH ingress rule added to cf-open-sg")
        except ClientError as e:
            print(f"[!] SG ingress rule skip/error: {e.response['Error']['Message']}")

    # 5) EC2 Instance with bad user-data
    try:
        images = ec2.describe_images(
            Filters=[{"Name":"name","Values":["amzn2-ami-hvm-2.0.*-x86_64-gp2"]}]
        )['Images']
        ami_id = sorted(images, key=lambda x: x['CreationDate'])[-1]['ImageId']
        inst = ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t2.micro",
            IamInstanceProfile={"Name":"CFTestProfile"},
            UserData="password=badpass123",
            MaxCount=1,
            MinCount=1
        )
        instance_id = inst['Instances'][0]['InstanceId']
        print(f"[+] EC2 instance {instance_id} launched")
        time.sleep(5)
        try:
            ec2.stop_instances(InstanceIds=[instance_id])
            print(f"[+] EC2 {instance_id} stopped")
        except ClientError as e:
            print(f"[!] EC2 stop skipped/error: {e.response['Error']['Message']}")
    except ClientError as e:
        print(f"[!] EC2 launch error: {e}")

    print("[*] Demo resource build complete.")
