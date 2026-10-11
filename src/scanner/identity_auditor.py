"""Local identity and privilege checks."""

import stat
from dataclasses import dataclass
from pathlib import Path

from scanner.models import AuditFinding, AuditStatus


@dataclass(frozen=True, slots=True)
class IdentityAuditor:
    """Audits system passwords, privileged groups, and sudoers permissions."""

    passwd_path: Path = Path("/etc/passwd")
    shadow_path: Path = Path("/etc/shadow")
    group_path: Path = Path("/etc/group")
    sudoers_path: Path = Path("/etc/sudoers")

    def audit(self) -> tuple[AuditFinding, ...]:
        """Returns identity findings without exposing password hashes."""
        try:
            passwd = self.passwd_path.read_text(encoding="utf-8")
            shadow = self.shadow_path.read_text(encoding="utf-8")
            groups = self.group_path.read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError) as error:
            return (
                AuditFinding(
                    module="Identity",
                    check_name="Account databases readable",
                    status=AuditStatus.ERROR,
                    details=str(error),
                    remediation="Run with sufficient read permissions.",
                ),
            )

        system_users = {
            fields[0]
            for line in passwd.splitlines()
            if len(fields := line.split(":")) >= 7
            and fields[0] != "root"
            and int(fields[2]) < 1000
            and fields[6] not in {"/usr/bin/nologin", "/sbin/nologin", "/bin/false"}
        }
        active_passwords = {
            fields[0]
            for line in shadow.splitlines()
            if len(fields := line.split(":")) >= 2
            and fields[1]
            and not fields[1].startswith(("!", "*"))
        }
        risky_users = sorted(system_users & active_passwords)
        privileged = self._privileged_members(groups)
        mode = stat.S_IMODE(self.sudoers_path.stat().st_mode) if self.sudoers_path.exists() else 0
        return (
            AuditFinding(
                module="Identity",
                check_name="System account passwords",
                status=AuditStatus.FAIL if risky_users else AuditStatus.PASS,
                details=(
                    f"System accounts with active passwords: {', '.join(risky_users)}"
                    if risky_users
                    else "No interactive system account has an active password."
                ),
                remediation="Lock unnecessary system accounts." if risky_users else None,
            ),
            AuditFinding(
                module="Identity",
                check_name="Privileged group membership",
                status=AuditStatus.WARNING if privileged else AuditStatus.PASS,
                details=f"Privileged users: {', '.join(privileged) or 'none'}.",
                remediation="Review every sudo or wheel member." if privileged else None,
            ),
            AuditFinding(
                module="Identity",
                check_name="sudoers permissions",
                status=AuditStatus.PASS if mode == 0o440 else AuditStatus.FAIL,
                details=f"sudoers mode is {mode:04o}.",
                remediation="Set /etc/sudoers to mode 0440." if mode != 0o440 else None,
            ),
        )

    @staticmethod
    def _privileged_members(groups: str) -> tuple[str, ...]:
        members: set[str] = set()
        for line in groups.splitlines():
            fields = line.split(":")
            if len(fields) >= 4 and fields[0] in {"sudo", "wheel"}:
                members.update(member for member in fields[3].split(",") if member)
        return tuple(sorted(members))
