# app/core/aws_connector.py
# Handles real or moto sessions + resource collection
import boto3
import logging
import os
import json

def _get_session(aws_key=None, aws_secret=None):
    """
    Returns a boto3.Session using:
    - Provided AWS key/secret (for multi-user support)
    - or AWS_PROFILE (from env)
    - or default shared-credentials chain
    """
    profile = os.getenv("AWS_PROFILE")
    if aws_key and aws_secret:
        return boto3.Session(
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
            region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        )
    return boto3.Session(profile_name=profile) if profile else boto3.Session()

def get_s3_client(region=None, aws_key=None, aws_secret=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session(aws_key, aws_secret).client("s3", region_name=region)

def get_iam_client(region=None, aws_key=None, aws_secret=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session(aws_key, aws_secret).client("iam", region_name=region)

def get_ec2_client(region=None, aws_key=None, aws_secret=None):
    region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    return _get_session(aws_key, aws_secret).client("ec2", region_name=region)

def get_caller_identity(aws_key=None, aws_secret=None):
    sts = boto3.client(
        "sts",
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret,
        region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    ) if aws_key and aws_secret else boto3.client("sts")
    resp = sts.get_caller_identity()
    arn = resp.get("Arn", "")
    username = arn.split("/")[-1] if "/" in arn else arn
    logging.info(f"Connected to AWS account: {resp['Account']} (ARN: {resp['Arn']}) | Username: {username}")
    return username

def get_aws_clients(region=None, mode="mock", user_index=0):
    """
    Returns a dict of boto3 clients keyed by service name.
    If .env contains AWS_CREDENTIALS_JSON, use the Nth set (user_index).
    """
    aws_key = aws_secret = None
    creds_json = os.getenv("AWS_CREDENTIALS_JSON")
    if creds_json:
        try:
            creds = json.loads(creds_json)
            if isinstance(creds, list) and len(creds) > user_index:
                aws_key = creds[user_index].get("key")
                aws_secret = creds[user_index].get("secret")
        except Exception as e:
            logging.error(f"Failed to parse AWS_CREDENTIALS_JSON: {e}")

    return {
        "s3":  get_s3_client(region, aws_key, aws_secret),
        "iam": get_iam_client(region, aws_key, aws_secret),
        "ec2": get_ec2_client(region, aws_key, aws_secret),
        "username": "mock-user" if mode == "mock" else get_caller_identity(aws_key, aws_secret)
    }
