"""Markdown report generation."""

from collections import Counter
from collections.abc import Sequence

from scanner.models import AuditFinding, AuditStatus


def render_markdown(findings: Sequence[AuditFinding]) -> str:
    """Renders findings as a portable Markdown audit report."""
    counts = Counter(finding.status for finding in findings)
    lines = [
        "# Homelab Security Audit",
        "",
        (
            f"Summary: {counts[AuditStatus.FAIL]} failed, "
            f"{counts[AuditStatus.WARNING]} warnings, {counts[AuditStatus.PASS]} passed."
        ),
        "",
        "| Module | Check | Status | Details | Remediation |",
        "|---|---|---|---|---|",
    ]
    lines.extend(
        "| "
        + " | ".join(
            (
                finding.module,
                finding.check_name,
                finding.status.value,
                finding.details.replace("|", "\\|"),
                (finding.remediation or "-").replace("|", "\\|"),
            ),
        )
        + " |"
        for finding in findings
    )
    return "\n".join(lines) + "\n"
