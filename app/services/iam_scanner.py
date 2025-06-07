import logging


def scan_iam_roles(iam_client):
    """
    Scans IAM roles for misconfigurations and security risks.

    What does this function do?
    - Identifies IAM roles with overly permissive policies (e.g., wildcard actions or resources).
    - Detects roles with attached policies that allow privilege escalation.
    - Flags roles missing MFA enforcement or with excessive permissions.
    - Aggregates multiple findings for a single role/policy and updates severity dynamically.

    Returns:
        List of findings, where each finding contains:
        - role_name: Name of the IAM role.
        - policy_name: Name of the attached policy.
        - risks: List of security issues detected.
        - recommendations: List of suggested remediation steps.
        - severity: Overall risk severity (Low, Medium, High).
        - mitre_tactic: MITRE ATT&CK tactic associated with the risk.
        - mitre_technique: MITRE ATT&CK technique associated with the risk.
    """
    logging.info("[*] Scanning IAM roles...")
    findings = []

    roles = iam_client.list_roles()['Roles']
    for role in roles:
        role_name = role['RoleName']
        policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']

        for policy_name in policies:
            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            statements = policy['PolicyDocument']['Statement']

            # Analyze policy statements
            role_findings = analyze_policy_statements(role_name, policy_name, statements, role)
            if role_findings:
                findings.append(role_findings)

    return findings


def analyze_policy_statements(role_name, policy_name, statements, role):
    """
    Analyzes policy statements for misconfigurations and aggregates findings.

    Returns:
        A dictionary containing:
        - role_name: Name of the IAM role.
        - policy_name: Name of the attached policy.
        - risks: List of security issues detected.
        - recommendations: List of suggested remediation steps.
        - severity: Overall risk severity (Low, Medium, High).
        - mitre_tactic: MITRE ATT&CK tactic associated with the risk.
        - mitre_technique: MITRE ATT&CK technique associated with the risk.
    """
    risks = []
    recommendations = []
    severity = "Low"  # Default severity
    mitre_tactic = []
    mitre_technique = []

    for stmt in statements:
        # Check for wildcard actions
        if check_wildcard_actions(stmt):
            risks.append("Wildcard IAM policy")
            recommendations.append("Restrict actions to least privilege")
            severity = update_severity(severity, "High")
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Exploitation for Privilege Escalation (T1068)")

        # Check for overly permissive resources
        if check_wildcard_resources(stmt):
            risks.append("Wildcard resource access")
            recommendations.append("Restrict resource access to specific resources")
            severity = update_severity(severity, "High")
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Exploitation for Privilege Escalation (T1068)")

        # Check for missing MFA enforcement
        if check_missing_mfa(stmt):
            risks.append("Missing MFA enforcement")
            recommendations.append("Add MFA enforcement to IAM policies")
            severity = update_severity(severity, "Medium")
            mitre_tactic.append("Access Control")
            mitre_technique.append("Modify Authentication Process: Disable or Modify MFA (T1556.006)")

        # Check for privilege escalation risks
        if check_privilege_escalation(stmt):
            risks.append("Privilege escalation via iam:PassRole")
            recommendations.append("Restrict iam:PassRole to specific roles")
            severity = update_severity(severity, "High")
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Account Manipulation: Cloud Accounts (T1098.003)")

    # Check for unused roles
    if check_unused_roles(role):
        risks.append("Unused IAM role")
        recommendations.append("Remove unused IAM roles to reduce attack surface")
        severity = update_severity(severity, "Low")
        mitre_tactic.append("Account Management")
        mitre_technique.append("Account Access Removal (T1531)")

    if risks:
        return {
            "role_name": role_name,
            "policy_name": policy_name,
            "risk": risks,
            "recommendations": recommendations,
            "severity": severity,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique
        }
    return None


# Sub-functions for modular checks
def check_wildcard_actions(stmt):
    """
    Checks if the policy statement allows wildcard actions (e.g., "Action": "*").
    """
    return stmt.get('Action') == "*" or stmt.get('Action') == ["*"]


def check_wildcard_resources(stmt):
    """
    Checks if the policy statement allows access to all resources (e.g., "Resource": "*").
    """
    return stmt.get('Resource') == "*" or stmt.get('Resource') == ["*"]


def check_missing_mfa(stmt):
    """
    Checks if the policy statement is missing MFA enforcement conditions.

    Cyber Concept:
    - MFA (Multi-Factor Authentication) adds an extra layer of security for sensitive actions.
    - Policies without MFA enforcement are more vulnerable to unauthorized access.
    """
    return 'Condition' not in stmt


def check_privilege_escalation(stmt):
    """
    Checks if the policy statement allows privilege escalation via iam:PassRole.

    Cyber Concept:
    - iam:PassRole allows a user to pass an IAM role to a service, potentially escalating privileges.
    - If unrestricted, attackers can use this to gain access to roles with higher permissions.
    """
    return "iam:PassRole" in stmt.get('Action', []) and stmt.get('Resource') == "*"


def check_unused_roles(role):
    """
    Checks if the IAM role has not been used recently (e.g., no LastUsedDate).

    Cyber Concept:
    - Unused roles increase the attack surface and should be removed to minimize risk.
    - Attackers can exploit unused roles if they are not properly monitored or secured.
    """
    last_used = role.get('RoleLastUsed', {}).get('LastUsedDate')
    return not last_used


def update_severity(current_severity, new_severity):
    """
    Updates the overall severity based on the new severity level.
    Severity levels: Low < Medium < High.
    """
    severity_levels = {"Low": 1, "Medium": 2, "High": 3}
    return new_severity if severity_levels[new_severity] > severity_levels[current_severity] else current_severity