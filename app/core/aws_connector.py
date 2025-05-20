# Handles moto sessions and resource collection
import boto3

def get_s3_client(region='us-west-1'):
    return boto3.client('s3', region_name=region)
