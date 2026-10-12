"""OpenSSH server hardening checks."""

from dataclasses import dataclass
from pathlib import Path

from scanner.models import AuditFinding, AuditStatus


@dataclass(frozen=True, slots=True)
class SSHAuditor:
    """Audits effective directives from a local sshd configuration file."""

    config_path: Path = Path("/etc/ssh/sshd_config")

    def audit(self) -> tuple[AuditFinding, ...]:
        """Returns root-login and password-authentication findings."""
        try:
            config = self._parse(self.config_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, PermissionError) as error:
            return (
                AuditFinding(
                    module="SSH",
                    check_name="Configuration readable",
                    status=AuditStatus.ERROR,
                    details=str(error),
                    remediation="Install OpenSSH server or grant read permission.",
                ),
            )

        root_login = config.get("permitrootlogin", "prohibit-password")
        password_auth = config.get("passwordauthentication", "yes")
        return (
            AuditFinding(
                module="SSH",
                check_name="Root login disabled",
                status=AuditStatus.PASS if root_login == "no" else AuditStatus.FAIL,
                details=f"PermitRootLogin is {root_login}.",
                remediation="Set PermitRootLogin no." if root_login != "no" else None,
            ),
            AuditFinding(
                module="SSH",
                check_name="Key-only authentication",
                status=AuditStatus.PASS if password_auth == "no" else AuditStatus.FAIL,
                details=f"PasswordAuthentication is {password_auth}.",
                remediation="Set PasswordAuthentication no after testing SSH keys."
                if password_auth != "no"
                else None,
            ),
        )

    @staticmethod
    def _parse(content: str) -> dict[str, str]:
        directives: dict[str, str] = {}
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition(" ")
            if separator:
                directives[key.lower()] = value.split()[0].lower()
        return directives
