"""Operating-system update and reboot checks."""

from dataclasses import dataclass

from scanner.models import AuditFinding, AuditStatus
from scanner.system import CommandRunner


@dataclass(frozen=True, slots=True)
class HealthAuditor:
    """Audits pending updates on Arch and Debian-family systems."""

    runner: CommandRunner
    reboot_required: bool

    def audit(self) -> tuple[AuditFinding, ...]:
        """Returns update and reboot findings for the detected package manager."""
        updates = self._pending_updates()
        return (
            AuditFinding(
                module="Health",
                check_name="Pending updates",
                status=AuditStatus.WARNING if updates else AuditStatus.PASS,
                details=f"{len(updates)} package updates are pending.",
                remediation="Review and install pending updates." if updates else None,
            ),
            AuditFinding(
                module="Health",
                check_name="Reboot required",
                status=AuditStatus.WARNING if self.reboot_required else AuditStatus.PASS,
                details="A reboot is required."
                if self.reboot_required
                else "No reboot marker exists.",
                remediation="Schedule a controlled reboot." if self.reboot_required else None,
            ),
        )

    def _pending_updates(self) -> tuple[str, ...]:
        if self.runner.available("pacman"):
            result = self.runner.run(("pacman", "-Qu"))
        elif self.runner.available("apt-get"):
            result = self.runner.run(("apt-get", "--just-print", "upgrade"))
        else:
            return ()
        return tuple(line for line in result.stdout.splitlines() if line.strip())
