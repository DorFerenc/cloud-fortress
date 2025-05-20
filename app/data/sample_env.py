# Simulated AWS environment setup using the moto library for mocking AWS services.

from moto import mock_s3, mock_iam, mock_ec2  # Importing the mock_s3 decorator to simulate S3 service.
import boto3  # AWS SDK for Python to interact with AWS services.

def setup_mock_s3_environment():
    """
    Sets up a simulated S3 environment using moto.

    This function creates two S3 buckets:
    1. A private bucket named 'private-bucket'.
    2. A public bucket named 'public-bucket' with public-read access.

    Returns:
        mock: The moto mock object, which must be stopped after use.

    AWS Regions:
    The region where a bucket is created is specified using the `LocationConstraint` parameter.
    The region matters because:
    - It determines the physical location of the data.
    - It affects latency when accessing the bucket.
    - It may have cost implications depending on the region.

    Common AWS Regions:
    | Region Name              | Location Constraint       |
    |--------------------------|---------------------------|
    | US East (N. Virginia)    | `us-east-1`              |
    | US East (Ohio)           | `us-east-2`              |
    | US West (N. California)  | `us-west-1`              |
    | US West (Oregon)         | `us-west-2`              |
    | Canada (Central)         | `ca-central-1`           |
    | Europe (Ireland)         | `eu-west-1`              |
    | Europe (London)          | `eu-west-2`              |
    | Europe (Frankfurt)       | `eu-central-1`           |
    | Asia Pacific (Tokyo)     | `ap-northeast-1`         |
    | Asia Pacific (Seoul)     | `ap-northeast-2`         |
    | Asia Pacific (Singapore) | `ap-southeast-1`         |
    | Asia Pacific (Sydney)    | `ap-southeast-2`         |
    | South America (São Paulo)| `sa-east-1`              |
    | Africa (Cape Town)       | `af-south-1`             |
    | Middle East (Bahrain)    | `me-south-1`             |
    | Middle East (Israel)     | `il-central-1`           |

    Note: The `LocationConstraint` must match the `region_name` used when creating the S3 client.
    """
    # Start the moto mock for S3.
    mock = mock_s3()
    mock.start()

    # Create an S3 client to interact with the mocked S3 service.
    s3 = boto3.client('s3', region_name='us-west-1')

    # Create a private bucket named 'private-bucket' in the 'us-west-1' region.
    s3.create_bucket(
        Bucket='private-bucket',
        CreateBucketConfiguration={'LocationConstraint': 'us-west-1'}
    )

    # Create a public bucket named 'public-bucket' in the 'us-west-1' region.
    s3.create_bucket(
        Bucket='public-bucket',
        CreateBucketConfiguration={'LocationConstraint': 'us-west-1'}
    )

    # Set the ACL (Access Control List) of 'public-bucket' to public-read.
    s3.put_bucket_acl(Bucket='public-bucket', ACL='public-read')

    # Return the mock object so it can be stopped later.
    return mock

def setup_mock_iam_environment():
    mock = mock_iam()
    mock.start()

    iam = boto3.client('iam')
    iam.create_role(
        RoleName='AdminRole',
        AssumeRolePolicyDocument='{}',
        Description='Overly permissive role'
    )
    iam.put_role_policy(
        RoleName='AdminRole',
        PolicyName='admin-policy',
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )

    return mock

def setup_mock_ec2_environment():
    mock = mock_ec2()
    mock.start()

    ec2 = boto3.client('ec2', region_name='us-west-1')

    # Create security group with open port
    sg = ec2.create_security_group(
        GroupName='open-sg',
        Description='Allows all inbound traffic'
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )

    # Create EC2 instance
    ec2.run_instances(
        ImageId='ami-12345678',
        InstanceType='t2.micro',
        MaxCount=1,
        MinCount=1,
        SecurityGroupIds=[sg['GroupId']],
        UserData='password=12345\naws_secret_access_key=AKIA...'
    )

    return mock
