def scan_s3_buckets(s3_client):
    findings = []

    response = s3_client.list_buckets()
    for bucket in response.get('Buckets', []):
        bucket_name = bucket['Name']
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)

        # Public access check
        is_public = any(
            grant.get('Grantee', {}).get('URI') ==
            'http://acs.amazonaws.com/groups/global/AllUsers'
            for grant in acl.get('Grants', [])
        )

        # Get encryption
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_status = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        except Exception:
            encryption_status = "None"

        # Get versioning
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_status = versioning.get('Status', 'Disabled')
        except Exception:
            versioning_status = "Unknown"

        # Get logging
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            logging_status = "Enabled" if 'LoggingEnabled' in logging else "Disabled"
        except Exception:
            logging_status = "Unknown"

        finding = {
            'resource_type': 'S3',
            'bucket_name': bucket_name,
            'public': is_public,
            'risk_level': 'High' if is_public else 'None',
            'misconfiguration_type': 'Public S3 Bucket' if is_public else None,
            'recommendation': 'Remove public access' if is_public else None,
            'encryption': encryption_status,
            'versioning': versioning_status,
            'logging': logging_status
        }
        findings.append(finding)

    return findings
