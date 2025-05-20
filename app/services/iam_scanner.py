import boto3  # AWS SDK for Python to interact with AWS services.

def scan_iam_roles():
    client = boto3.client('iam')
    findings = []

    roles = client.list_roles()['Roles']
    for role in roles:
        role_name = role['RoleName']
        policies = client.list_role_policies(RoleName=role_name)['PolicyNames']

        for policy_name in policies:
            policy = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            statements = policy['PolicyDocument']['Statement']
            for stmt in statements:
                if stmt['Action'] == "*" or stmt['Action'] == ["*"]:
                    findings.append({
                        "role_name": role_name,
                        "policy_name": policy_name,
                        "risk": "Wildcard IAM policy",
                        "recommendation": "Restrict actions to least privilege"
                    })
    return findings
