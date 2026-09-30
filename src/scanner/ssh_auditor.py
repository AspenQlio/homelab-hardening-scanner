import os
from .models import AuditFinding, AuditStatus

class SSHAuditor:
    def __init__(self, config_path: str = "/etc/ssh/sshd_config"):
        self.config_path = config_path

    def audit(self) -> list[AuditFinding]:
        findings = []
        
        if not os.path.exists(self.config_path):
            findings.append(AuditFinding(
                module="SSH",
                check_name="Config File Exists",
                status=AuditStatus.ERROR,
                details=f"Could not find {self.config_path}",
                remediation="Ensure OpenSSH server is installed."
            ))
            return findings

        # Read config ignoring comments and empty lines
        config = {}
        try:
            with open(self.config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].lower()
                        val = parts[1].lower()
                        config[key] = val
        except PermissionError:
            findings.append(AuditFinding(
                module="SSH",
                check_name="Read Permissions",
                status=AuditStatus.ERROR,
                details=f"Permission denied reading {self.config_path}",
                remediation="Run the scanner with elevated privileges."
            ))
            return findings

        # Check 1: Root Login
        permit_root = config.get("permitrootlogin", "prohibit-password") # Default in modern SSH
        if permit_root == "yes":
            findings.append(AuditFinding(
                module="SSH",
                check_name="Root Login Disabled",
                status=AuditStatus.FAIL,
                details="PermitRootLogin is set to 'yes'.",
                remediation="Set 'PermitRootLogin no' in sshd_config."
            ))
        elif permit_root == "prohibit-password":
            findings.append(AuditFinding(
                module="SSH",
                check_name="Root Login Disabled",
                status=AuditStatus.WARNING,
                details="PermitRootLogin is 'prohibit-password'. Keys are required, but 'no' is safer.",
                remediation="Set 'PermitRootLogin no' if root SSH is not strictly needed."
            ))
        else:
            findings.append(AuditFinding(
                module="SSH",
                check_name="Root Login Disabled",
                status=AuditStatus.PASS,
                details=f"PermitRootLogin is securely set to '{permit_root}'."
            ))

        # Check 2: Password Authentication
        pass_auth = config.get("passwordauthentication", "yes")
        if pass_auth == "yes":
            findings.append(AuditFinding(
                module="SSH",
                check_name="Key-Based Auth Only",
                status=AuditStatus.FAIL,
                details="PasswordAuthentication is enabled. Vulnerable to brute-force.",
                remediation="Setup SSH keys and set 'PasswordAuthentication no'."
            ))
        else:
            findings.append(AuditFinding(
                module="SSH",
                check_name="Key-Based Auth Only",
                status=AuditStatus.PASS,
                details="PasswordAuthentication is disabled."
            ))

        return findings
