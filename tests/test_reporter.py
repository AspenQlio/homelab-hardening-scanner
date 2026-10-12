from scanner.models import AuditFinding, AuditStatus
from scanner.reporter import render_markdown


def test_report_contains_summary_and_remediation() -> None:
    # Given
    findings = (
        AuditFinding(
            module="SSH",
            check_name="Password authentication",
            status=AuditStatus.FAIL,
            details="Password login is enabled.",
            remediation="Disable PasswordAuthentication.",
        ),
    )

    # When
    report = render_markdown(findings)

    # Then
    assert "1 failed" in report
    assert "Disable PasswordAuthentication." in report
