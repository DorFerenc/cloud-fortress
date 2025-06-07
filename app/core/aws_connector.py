# app/core/aws_connector.py
# Handles real or moto sessions + resource collection
import boto3
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

def get_aws_clients(region=None):
    """
    Returns a dict of boto3 clients keyed by service name.
    """
    return {
        "s3":  get_s3_client(region),
        "iam": get_iam_client(region),
        "ec2": get_ec2_client(region)
    }
