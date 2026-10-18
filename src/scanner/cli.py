"""Command-line entry point for the security scanner."""

import grp
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from scanner.docker_auditor import DockerAuditor
from scanner.firewall_auditor import FirewallAuditor
from scanner.health_auditor import HealthAuditor
from scanner.identity_auditor import IdentityAuditor
from scanner.models import AuditFinding, AuditStatus
from scanner.reporter import render_markdown
from scanner.ssh_auditor import SSHAuditor
from scanner.system import SystemCommandRunner

app = typer.Typer(add_completion=False)


@app.callback()
def root() -> None:
    """Audit Linux security posture without changing the system."""


def _docker_members() -> tuple[str, ...]:
    try:
        return tuple(sorted(grp.getgrnam("docker").gr_mem))
    except KeyError:
        return ()


def _collect_findings() -> tuple[AuditFinding, ...]:
    runner = SystemCommandRunner()
    auditors = (
        SSHAuditor(),
        FirewallAuditor(runner),
        IdentityAuditor(),
        DockerAuditor(runner, _docker_members(), os.getenv("DOCKER_HOST", "")),
        HealthAuditor(runner, Path("/var/run/reboot-required").exists()),
    )
    return tuple(finding for auditor in auditors for finding in auditor.audit())


def _render_terminal(findings: tuple[AuditFinding, ...]) -> None:
    table = Table(title="Homelab Security Audit")
    table.add_column("Module")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Details")
    for finding in findings:
        style = {
            AuditStatus.PASS: "green",
            AuditStatus.FAIL: "red",
            AuditStatus.WARNING: "yellow",
            AuditStatus.ERROR: "magenta",
        }[finding.status]
        table.add_row(
            finding.module, finding.check_name, f"[{style}]{finding.status.value}", finding.details
        )
    Console().print(table)


@app.command()
def scan(
    report: Annotated[
        Path | None,
        typer.Option("--report", help="Write a Markdown report to this path."),
    ] = None,
) -> None:
    """Runs every read-only security audit."""
    findings = _collect_findings()
    _render_terminal(findings)
    if report is not None:
        _ = report.write_text(render_markdown(findings), encoding="utf-8")


def main() -> None:
    """Starts the Typer application."""
    app()


if __name__ == "__main__":
    default_report = Path(f"audit_{datetime.now(tz=UTC):%Y%m%d}.md")
    scan(default_report)
