#!/usr/bin/env python3

"""
PLM Security Configuration Auditor
-----------------------------------

Defensive configuration checker for Windchill / ENOVIA environments.

The script evaluates an exported/approved configuration file for:
- MFA
- SSO
- TLS
- Audit logging
- Default administrator accounts
- External sharing
- Service-account privileges
- Dormant accounts
- Privileged users
- API token lifetime

Usage:
    python plm_security_audit.py sample-config.json
"""

import json
import sys
from pathlib import Path


RULES = {
    "mfa_enabled": {
        "expected": True,
        "severity": "CRITICAL",
        "message": "MFA is not enabled."
    },
    "sso_enabled": {
        "expected": True,
        "severity": "HIGH",
        "message": "Centralized SSO is not enabled."
    },
    "tls_enabled": {
        "expected": True,
        "severity": "CRITICAL",
        "message": "TLS protection is disabled."
    },
    "audit_logging": {
        "expected": True,
        "severity": "HIGH",
        "message": "Security audit logging is disabled."
    },
    "default_admin_enabled": {
        "expected": False,
        "severity": "CRITICAL",
        "message": "Default administrative account is enabled."
    },
    "external_sharing_enabled": {
        "expected": False,
        "severity": "HIGH",
        "message": "Unrestricted external sharing is enabled."
    }
}


def audit_boolean_settings(config):
    """Check security settings against approved values."""

    findings = []

    for setting, rule in RULES.items():
        actual = config.get(setting)

        if actual != rule["expected"]:
            findings.append({
                "category": "Configuration",
                "setting": setting,
                "severity": rule["severity"],
                "finding": rule["message"],
                "actual": actual,
                "expected": rule["expected"]
            })

    return findings


def audit_accounts(config):
    """Check accounts for excessive privilege and dormancy."""

    findings = []

    for account in config.get("accounts", []):
        username = account.get("username", "UNKNOWN")

        if account.get("admin") is True:
            findings.append({
                "category": "Authorization",
                "setting": username,
                "severity": "HIGH",
                "finding": "Account has administrative privileges.",
                "actual": "admin",
                "expected": "least privilege"
            })

        if account.get("dormant") is True:
            findings.append({
                "category": "Identity",
                "setting": username,
                "severity": "MEDIUM",
                "finding": "Dormant account remains enabled.",
                "actual": "dormant/enabled",
                "expected": "disabled or reviewed"
            })

    return findings


def audit_service_accounts(config):
    """Check PLM integration/service accounts."""

    findings = []

    for account in config.get("service_accounts", []):
        name = account.get("name", "UNKNOWN")
        role = account.get("role", "").lower()

        if role == "administrator":
            findings.append({
                "category": "Service Account",
                "setting": name,
                "severity": "CRITICAL",
                "finding": (
                    "Integration service account has administrator "
                    "privileges."
                ),
                "actual": role,
                "expected": "application-specific role"
            })

        if account.get("long_lived_token") is True:
            findings.append({
                "category": "API Security",
                "setting": name,
                "severity": "HIGH",
                "finding": "Service account uses a long-lived token.",
                "actual": "long-lived",
                "expected": "short-lived/rotated credential"
            })

    return findings


def audit_api_configuration(config):
    """Check API security configuration."""

    findings = []

    api = config.get("api", {})

    if api.get("authentication") == "none":
        findings.append({
            "category": "API Security",
            "setting": "authentication",
            "severity": "CRITICAL",
            "finding": "API authentication is disabled.",
            "actual": "none",
            "expected": "authenticated"
        })

    if api.get("object_level_authorization") is not True:
        findings.append({
            "category": "API Security",
            "setting": "object_level_authorization",
            "severity": "CRITICAL",
            "finding": (
                "Object-level authorization is not explicitly enabled."
            ),
            "actual": api.get("object_level_authorization"),
            "expected": True
        })

    if api.get("tls") is not True:
        findings.append({
            "category": "API Security",
            "setting": "tls",
            "severity": "HIGH",
            "finding": "API traffic is not protected by TLS.",
            "actual": api.get("tls"),
            "expected": True
        })

    return findings


def calculate_risk(findings):
    """Convert severity into a simple numeric score."""

    weights = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 1
    }

    return sum(weights.get(f["severity"], 0) for f in findings)


def print_report(findings):
    print("\nPLM SECURITY AUDIT")
    print("=" * 70)

    if not findings:
        print("[PASS] No configured security gaps detected.")
        return

    for finding in findings:
        print(
            f"\n[{finding['severity']}] "
            f"{finding['category']} / {finding['setting']}"
        )

        print(f"Finding : {finding['finding']}")
        print(f"Actual  : {finding['actual']}")
        print(f"Expected: {finding['expected']}")

    score = calculate_risk(findings)

    print("\n" + "=" * 70)
    print(f"Risk score: {score}")

    critical = sum(
        1 for f in findings if f["severity"] == "CRITICAL"
    )
    high = sum(
        1 for f in findings if f["severity"] == "HIGH"
    )

    print(f"Critical findings: {critical}")
    print(f"High findings    : {high}")


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python plm_security_audit.py "
            "sample-config.json"
        )
        sys.exit(1)

    config_file = Path(sys.argv[1])

    try:
        with config_file.open("r", encoding="utf-8") as file:
            config = json.load(file)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {config_file}")
        sys.exit(1)

    except json.JSONDecodeError as error:
        print(f"[ERROR] Invalid JSON: {error}")
        sys.exit(1)

    findings = []

    findings.extend(audit_boolean_settings(config))
    findings.extend(audit_accounts(config))
    findings.extend(audit_service_accounts(config))
    findings.extend(audit_api_configuration(config))

    print_report(findings)


if __name__ == "__main__":
    main()
