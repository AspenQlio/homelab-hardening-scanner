"""Docker privilege and daemon exposure checks."""

from dataclasses import dataclass

from scanner.models import AuditFinding, AuditStatus
from scanner.system import CommandRunner


@dataclass(frozen=True, slots=True)
class DockerAuditor:
    """Audits Docker access without modifying containers."""

    runner: CommandRunner
    docker_group_members: tuple[str, ...]
    docker_host: str

    def audit(self) -> tuple[AuditFinding, ...]:
        """Returns findings for group access, privileged mode, and TCP exposure."""
        findings = [
            AuditFinding(
                module="Docker",
                check_name="Docker group membership",
                status=AuditStatus.WARNING if self.docker_group_members else AuditStatus.PASS,
                details=f"Docker group members: {', '.join(self.docker_group_members) or 'none'}.",
                remediation="Review members because Docker access is root-equivalent."
                if self.docker_group_members
                else None,
            ),
            AuditFinding(
                module="Docker",
                check_name="Unencrypted daemon socket",
                status=AuditStatus.FAIL
                if "tcp://" in self.docker_host and ":2375" in self.docker_host
                else AuditStatus.PASS,
                details=f"DOCKER_HOST is {self.docker_host or 'local Unix socket'}.",
                remediation="Disable TCP port 2375 or require mutual TLS."
                if ":2375" in self.docker_host
                else None,
            ),
        ]
        if not self.runner.available("docker"):
            findings.append(
                AuditFinding(
                    module="Docker",
                    check_name="Docker inspection",
                    status=AuditStatus.WARNING,
                    details="Docker CLI is unavailable.",
                ),
            )
            return tuple(findings)

        containers = self.runner.run(("docker", "ps", "--quiet"))
        for container_id in containers.stdout.split():
            result = self.runner.run(
                (
                    "docker",
                    "inspect",
                    "--format",
                    "{{.Name}}|{{.HostConfig.Privileged}}",
                    container_id,
                ),
            )
            name, separator, privileged = result.stdout.strip().partition("|")
            if separator and privileged.lower() == "true":
                findings.append(
                    AuditFinding(
                        module="Docker",
                        check_name="Privileged container",
                        status=AuditStatus.FAIL,
                        details=f"Container {name.lstrip('/')} runs in privileged mode.",
                        remediation="Remove privileged mode and grant only required capabilities.",
                    ),
                )
        if not any(finding.check_name == "Privileged container" for finding in findings):
            findings.append(
                AuditFinding(
                    module="Docker",
                    check_name="Privileged containers",
                    status=AuditStatus.PASS,
                    details="No running container uses privileged mode.",
                ),
            )
        return tuple(findings)
