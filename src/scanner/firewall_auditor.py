"""Firewall state and default-policy checks."""

from dataclasses import dataclass

from scanner.models import AuditFinding, AuditStatus
from scanner.system import CommandRunner


@dataclass(frozen=True, slots=True)
class FirewallAuditor:
    """Audits UFW, firewalld, or iptables without changing rules."""

    runner: CommandRunner

    def audit(self) -> tuple[AuditFinding, ...]:
        """Returns findings for the first supported firewall backend."""
        if self.runner.available("ufw"):
            findings = self._audit_ufw()
        elif self.runner.available("firewall-cmd"):
            findings = self._audit_firewalld()
        elif self.runner.available("iptables"):
            findings = self._audit_iptables()
        else:
            findings = (
                AuditFinding(
                    module="Firewall",
                    check_name="Firewall backend",
                    status=AuditStatus.FAIL,
                    details="No supported firewall backend was found.",
                    remediation="Install and enable UFW, firewalld, or iptables.",
                ),
            )
        return findings + self._audit_dangerous_ports()

    def _audit_dangerous_ports(self) -> tuple[AuditFinding, ...]:
        if not self.runner.available("ss"):
            return ()
        result = self.runner.run(("ss", "-lntH"))
        dangerous = tuple(
            port
            for port in (21, 23)
            if any(address.rsplit(":", 1)[-1] == str(port) for address in result.stdout.split())
        )
        return (
            AuditFinding(
                module="Firewall",
                check_name="Dangerous listening ports",
                status=AuditStatus.FAIL if dangerous else AuditStatus.PASS,
                details=(
                    f"Dangerous TCP ports listening: {', '.join(map(str, dangerous)) or 'none'}."
                ),
                remediation="Disable plaintext FTP and Telnet services." if dangerous else None,
            ),
        )

    def _audit_ufw(self) -> tuple[AuditFinding, ...]:
        result = self.runner.run(("ufw", "status", "verbose"))
        output = result.stdout.lower()
        active = result.returncode == 0 and "status: active" in output
        deny_incoming = "default: deny (incoming)" in output
        return (
            self._finding("Firewall enabled", active, "UFW is active."),
            self._finding("Default incoming policy", deny_incoming, "UFW denies incoming traffic."),
        )

    def _audit_firewalld(self) -> tuple[AuditFinding, ...]:
        result = self.runner.run(("firewall-cmd", "--state"))
        active = result.returncode == 0 and result.stdout.strip() == "running"
        return (self._finding("Firewall enabled", active, "firewalld is running."),)

    def _audit_iptables(self) -> tuple[AuditFinding, ...]:
        result = self.runner.run(("iptables", "-S", "INPUT"))
        deny_incoming = result.returncode == 0 and "-P INPUT DROP" in result.stdout
        return (
            self._finding(
                "Default incoming policy", deny_incoming, "iptables defaults INPUT to DROP."
            ),
        )

    @staticmethod
    def _finding(check_name: str, passed: bool, success_details: str) -> AuditFinding:
        return AuditFinding(
            module="Firewall",
            check_name=check_name,
            status=AuditStatus.PASS if passed else AuditStatus.FAIL,
            details=success_details if passed else f"{check_name} is not secure.",
            remediation=None
            if passed
            else "Enable the firewall and deny unsolicited incoming traffic.",
        )
