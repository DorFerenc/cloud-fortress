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
        - severity: Overall risk severity (1-5).
        - mitre_tactic: MITRE ATT&CK tactic associated with the risk.
        - mitre_technique: MITRE ATT&CK technique associated with the risk.
    """
    logging.info("[*] Scanning IAM roles...")
    findings = []

    try:
        roles = iam_client.list_roles()['Roles']
        logging.info(f"[*] Found {len(roles)} IAM roles.")
    except Exception as e:
        logging.error(f"[!] Failed to list IAM roles: {e}")
        return findings

    for role in roles:
        role_name = role['RoleName']
        try:
            policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
            logging.info(f"[*] Role '{role_name}' has {len(policies)} inline policies.")
        except Exception as e:
            logging.error(f"[!] Failed to list policies for role '{role_name}': {e}")
            continue

        for policy_name in policies:
            try:
                policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                statements = policy['PolicyDocument']['Statement']
                logging.debug(f"[*] Analyzing policy '{policy_name}' for role '{role_name}'.")
            except Exception as e:
                logging.error(f"[!] Failed to get policy '{policy_name}' for role '{role_name}': {e}")
                continue

            # Analyze policy statements
            role_findings = analyze_policy_statements(role_name, policy_name, statements, role)
            if role_findings:
                logging.info(f"[!] Findings for role '{role_name}', policy '{policy_name}': {role_findings['risk']}")
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
        - severity: Overall risk severity (1-5).
        - mitre_tactic: MITRE ATT&CK tactic associated with the risk.
        - mitre_technique: MITRE ATT&CK technique associated with the risk.
    """
    risks = []
    recommendations = []
    severity = 1  # Default severity (1 = Low, 5 = Critical)
    mitre_tactic = []
    mitre_technique = []

    for stmt in statements:
        # Check for wildcard actions
        if check_wildcard_actions(stmt):
            risks.append("Wildcard IAM policy")
            recommendations.append("Restrict actions to least privilege")
            severity = update_severity(severity, 5)
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Exploitation for Privilege Escalation (T1068)")
            logging.warning(f"[!] Wildcard action detected in policy '{policy_name}' for role '{role_name}'.")

        # Check for overly permissive resources
        if check_wildcard_resources(stmt):
            risks.append("Wildcard resource access")
            recommendations.append("Restrict resource access to specific resources")
            severity = update_severity(severity, 5)
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Exploitation for Privilege Escalation (T1068)")
            logging.warning(f"[!] Wildcard resource detected in policy '{policy_name}' for role '{role_name}'.")

        # Check for missing MFA enforcement
        if check_missing_mfa(stmt):
            risks.append("Missing MFA enforcement")
            recommendations.append("Add MFA enforcement to IAM policies")
            severity = update_severity(severity, 3)
            mitre_tactic.append("Access Control")
            mitre_technique.append("Modify Authentication Process: Disable or Modify MFA (T1556.006)")
            logging.info(f"[*] Missing MFA enforcement in policy '{policy_name}' for role '{role_name}'.")

        # Check for privilege escalation risks
        if check_privilege_escalation(stmt):
            risks.append("Privilege escalation via iam:PassRole")
            recommendations.append("Restrict iam:PassRole to specific roles")
            severity = update_severity(severity, 5)
            mitre_tactic.append("Privilege Escalation")
            mitre_technique.append("Account Manipulation: Cloud Accounts (T1098.003)")
            logging.warning(f"[!] Privilege escalation risk (iam:PassRole) in policy '{policy_name}' for role '{role_name}'.")

    # Check for unused roles
    if check_unused_roles(role):
        risks.append("Unused IAM role")
        recommendations.append("Remove unused IAM roles to reduce attack surface")
        severity = update_severity(severity, 2)
        mitre_tactic.append("Account Management")
        mitre_technique.append("Account Access Removal (T1531)")
        logging.info(f"[*] Unused IAM role detected: '{role_name}'.")

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
    Severity levels: 1 (Low) < 2 < 3 < 4 < 5 (Critical).
    """
    return max(current_severity, new_severity)