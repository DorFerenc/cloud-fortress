# app/core/aws_connector.py
# Handles real or moto sessions + resource collection
import boto3
import logging
import os

def _get_session():
    """
    Returns a boto3.Session that honours either:
    - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (env vars loaded via .env)
    - or an AWS_PROFILE name (also from env)
    - or default shared-credentials chain
    """
    profile = os.getenv("AWS_PROFILE")
    return boto3.Session(profile_name=profile) if profile else boto3.Session()

def get_s3_client(region=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session().client("s3", region_name=region)

def get_iam_client(region=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session().client("iam", region_name=region)

def get_ec2_client(region=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session().client("ec2", region_name=region)

def get_security_groups(region=None):
    """
    Returns a list of security groups in the current AWS account/region.
    """
    ec2 = get_ec2_client(region)
    try:
        response = ec2.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
        logging.info(f"Retrieved {len(security_groups)} security groups from AWS.")
        return security_groups
    except Exception as e:
        logging.error(f"Failed to retrieve security groups: {e}")
        return []

def get_caller_identity():
    sts = boto3.client("sts")
    resp = sts.get_caller_identity()
    logging.info(f"Connected to AWS account: {resp['Account']} (ARN: {resp['Arn']})")
    arn = resp.get("Arn", "")
    username = arn.split("/")[-1] if "/" in arn else arn
    logging.info(f"Connected to AWS account: {resp['Account']} (ARN: {resp['Arn']}) | Username: {username}")
    return username

def get_aws_clients(region=None):
    """
    Returns a dict of boto3 clients keyed by service name.
    """
    return {
        "s3":  get_s3_client(region),
        "iam": get_iam_client(region),
        "ec2": get_ec2_client(region),
        "security_groups": get_security_groups(region),
        "username": get_caller_identity()
    }
