import logging

MISCONFIG_RULES = {
    "public_acl": {
        "check": lambda acl: acl,
        "message": "Bucket has public ACL.",
        "score": 3,
        "tactic": "Initial Access",
        "technique": "Expose Storage to Internet (T1530)"
    },
    "public_policy": {
        "check": lambda policy: policy,
        "message": "Bucket has public policy.",
        "score": 3,
        "tactic": "Initial Access",
        "technique": "Expose Storage to Internet (T1530)"
    },
    "no_encryption": {
        "check": lambda enc: enc == "None",
        "message": "Bucket has no encryption.",
        "score": 2,
        "tactic": "Defense Evasion",
        "technique": "No Encryption (custom)"
    },
    "no_logging": {
        "check": lambda log: log in ["Disabled", "Unknown"],
        "message": "Bucket logging is not enabled.",
        "score": 1,
        "tactic": "Defense Evasion",
        "technique": "Disable Logging (T1562.001)"
    },
    "no_versioning": {
        "check": lambda ver: ver in ["Disabled", "Suspended", "Unknown"],
        "message": "Bucket versioning is not fully enabled.",
        "score": 1,
        "tactic": "Impact",
        "technique": "Uncategorized S3 Risk"
    }
}


def scan_s3_buckets(s3_client):
    """
    Scans S3 buckets for misconfigurations and security risks.

    Findings include:
    - Public access (via ACLs and bucket policies)
    - Encryption status
    - Versioning status
    - Logging configuration
    - Granular risk levels (High, Medium, Low)

    Performance Optimization:
    - Uses caching to avoid redundant API calls for large accounts.
    - Divides checks into sub-functions for modularity and readability.

    Returns:
        List of findings, where each finding contains:
        - bucket_name: Name of the bucket
        - risk_level: High, Medium, or Low
        - misconfiguration_type: Type of misconfiguration
        - recommendation: Suggested remediation steps
        - encryption: Encryption status
        - versioning: Versioning status
        - logging: Logging status
        - bucket_policy: Summary of bucket policy (if applicable)
    """
    findings = []

    # Cache bucket details to avoid redundant API calls
    bucket_cache = s3_client.list_buckets().get('Buckets', [])
    logging.info(f"[*] Found {len(bucket_cache)} buckets to scan.")

    for bucket in bucket_cache:
        bucket_name = bucket['Name']
        logging.info(f"[*] Scanning bucket: {bucket_name}")

        # Perform checks
        public_acl = check_public_acl(s3_client, bucket_name)
        public_policy, policy_document = check_public_policy(s3_client, bucket_name)
        encryption_status = check_encryption(s3_client, bucket_name)
        versioning_status = check_versioning(s3_client, bucket_name)
        logging_status = check_logging(s3_client, bucket_name)

        # Determine risk level
        # risk_level, misconfiguration_type, recommendation = determine_risk_level(
        #     public_acl, public_policy, encryption_status, logging_status, versioning_status
        # )
        risk_level, misconfiguration_type, recommendation, severity, mitre_tactic, mitre_technique = determine_risk_level(
            public_acl, public_policy, encryption_status, logging_status, versioning_status
        )


        # Add finding
        finding = {
            'resource_type': 'S3',
            'bucket_name': bucket_name,
            'public_acl': public_acl,
            'public_policy': public_policy,
            'risk_level': risk_level,
            'misconfiguration_type': misconfiguration_type,
            'recommendation': recommendation,
            'encryption': encryption_status,
            'versioning': versioning_status,
            'logging': logging_status,
            'bucket_policy': policy_document if public_policy else "No public policy",
            'severity': severity,
            'mitre_tactic': mitre_tactic,
            'mitre_technique': mitre_technique,
            'host': f"{bucket_name}.s3.amazonaws.com",
            'port': 443,
            'ip': "N/A"
        }

        findings.append(finding)

    logging.info("[*] Finished scanning S3 buckets.")
    return findings


# Sub-functions for modularity
def check_public_acl(s3_client, bucket_name):
    """
    Checks if the bucket is publicly accessible via ACLs.

    What is an ACL (Access Control List)?
    - An ACL is a set of rules that define who can access the bucket and what actions they can perform.
    - ACLs are attached directly to the bucket and can grant permissions to specific users, groups, or everyone.

    What does "publicly accessible" mean?
    - A bucket is publicly accessible if the ACL grants access to "AllUsers" (anyone on the internet).
    - Public access is a security risk as it exposes the bucket's contents to unauthorized users.

    Other options:
    - Buckets can be restricted to specific AWS accounts, IAM roles, or users using ACLs.
    """
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        return any(
            grant.get('Grantee', {}).get('URI') ==
            'http://acs.amazonaws.com/groups/global/AllUsers'
            for grant in acl.get('Grants', [])
        )
    except Exception:
        return False


def check_public_policy(s3_client, bucket_name):
    """
    Checks if the bucket is publicly accessible via bucket policies.

    What is a bucket policy?
    - A bucket policy is a JSON document that defines permissions for accessing the bucket.
    - It allows fine-grained control over who can access the bucket and what actions they can perform.

    What does "publicly accessible" mean?
    - A bucket is publicly accessible if the policy allows access to "Principal: *" (any user on the internet).
    - Public access is a security risk as it exposes the bucket's contents to unauthorized users.

    Other options:
    - Buckets can be restricted to specific AWS accounts, IAM roles, or users.
    """
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_document = policy.get('Policy', {})
        is_public_policy = '"Effect":"Allow"' in policy_document and '"Principal":"*"' in policy_document
        return is_public_policy, policy_document
    except Exception:
        return False, None


def check_encryption(s3_client, bucket_name):
    """
    Checks the encryption status of the bucket.

    What is bucket encryption?
    - Encryption protects data stored in the bucket by encoding it, making it unreadable without the decryption key.
    - AWS supports server-side encryption (SSE), which automatically encrypts data at rest.

    Types of encryption:
    - "AES256": Standard encryption algorithm provided by AWS.
    - "aws:kms": Encryption using AWS Key Management Service (KMS) for more control over encryption keys.

    Why is encryption important?
    - Encryption ensures that even if the bucket is compromised, the data remains secure.
    """
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        return encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
    except Exception:
        return "None"


def check_versioning(s3_client, bucket_name):
    """
    Checks the versioning status of the bucket.

    What is bucket versioning?
    - Versioning allows you to keep multiple versions of objects in the bucket.
    - It protects against accidental overwrites or deletions by retaining older versions.

    Status options:
    - "Enabled": Versioning is active, and multiple versions of objects are stored.
    - "Suspended": Versioning is temporarily disabled, but previous versions are retained.
    - "Disabled": Versioning is not enabled, and only the latest version of objects is stored.

    Why is versioning important?
    - It helps recover from accidental changes or deletions and provides an audit trail for object changes.
    """
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return versioning.get('Status', 'Disabled')
    except Exception:
        return "Unknown"


def check_logging(s3_client, bucket_name):
    """
    Checks the logging configuration of the bucket.

    What is bucket logging?
    - Logging records access requests to the bucket, including who accessed it and what actions were performed.
    - Logs are stored in another S3 bucket specified in the logging configuration.

    Status options:
    - "Enabled": Logging is active, and access requests are recorded.
    - "Disabled": Logging is not configured, and access requests are not tracked.

    Why is logging important?
    - Logging provides visibility into bucket activity, helping detect unauthorized access or suspicious behavior.
    - It is essential for auditing and compliance purposes.
    """
    try:
        logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
        return "Enabled" if 'LoggingEnabled' in logging_config else "Disabled"
    except Exception:
        return "Unknown"

def determine_risk_level(public_acl, public_policy, encryption_status, logging_status, versioning_status):
    """
    Determines the risk level based on bucket configuration.

    Returns:
        Tuple of (risk_level, misconfiguration_type, recommendation, severity, mitre_tactic, mitre_technique)
    """
    config_inputs = {
        "public_acl": public_acl,
        "public_policy": public_policy,
        "no_encryption": encryption_status,
        "no_logging": logging_status,
        "no_versioning": versioning_status
    }

    issues = []
    risk_score = 0
    matched_mitre = None

    for key, rule in MISCONFIG_RULES.items():
        value = config_inputs.get(key)
        if rule["check"](value):
            issues.append(rule["message"])
            risk_score += rule["score"]
            if matched_mitre is None:
                matched_mitre = (rule["tactic"], rule["technique"])

    if risk_score >= 6:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    misconfiguration_type = "; ".join(issues) if issues else "No significant issues"
    recommendation = generate_recommendation(public_acl, public_policy, encryption_status, logging_status, versioning_status)
    # severity = {"High": 4, "Medium": 3, "Low": 2}.get(risk_level, 1)
    severity = risk_level

    mitre_tactic, mitre_technique = matched_mitre or ("Impact", "Uncategorized S3 Risk")

    return risk_level, misconfiguration_type, recommendation, severity, mitre_tactic, mitre_technique

def generate_recommendation(public_acl, public_policy, encryption_status, logging_status, versioning_status):
    """
    Generates a human-readable recommendation based on misconfiguration.
    """
    recs = []

    if public_acl:
        recs.append("Remove public ACL to restrict anonymous access.")
    if public_policy:
        recs.append("Restrict bucket policy to trusted users only.")
    if encryption_status == "None":
        recs.append("Enable server-side encryption to protect data at rest.")
    if logging_status in ["Disabled", "Unknown"]:
        recs.append("Enable logging to monitor access and usage.")
    if versioning_status in ["Disabled", "Suspended", "Unknown"]:
        recs.append("Enable versioning to protect against accidental deletions or overwrites.")

    return " ".join(recs) if recs else "Bucket is securely configured."

