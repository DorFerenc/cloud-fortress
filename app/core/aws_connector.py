# Handles moto sessions and resource collection
import boto3

def get_s3_client(region='us-west-1'):
    return boto3.client('s3', region_name=region)

def get_iam_client(region='us-west-1'):
    return boto3.client('iam', region_name=region)

def get_ec2_client(region='us-west-1'):
    return boto3.client('ec2', region_name=region)

def get_aws_clients(region='us-west-1'):
    """
    Returns a dictionary of all AWS clients needed for scanning.
    """
    return {
        's3': get_s3_client(region),
        'iam': get_iam_client(region),
        'ec2': get_ec2_client(region)
    }
