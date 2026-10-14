from scanner.firewall_auditor import FirewallAuditor
from scanner.models import AuditStatus
from scanner.system import CommandResult
from tests.fakes import FakeRunner


def test_firewall_passes_when_ufw_is_active_and_denies_incoming() -> None:
    # Given
    runner = FakeRunner(
        available_commands={"ufw"},
        results={
            ("ufw", "status", "verbose"): CommandResult(
                returncode=0,
                stdout="Status: active\nDefault: deny (incoming), allow (outgoing)",
                stderr="",
            )
        },
    )

    # When
    findings = FirewallAuditor(runner).audit()

    # Then
    assert {finding.status for finding in findings} == {AuditStatus.PASS}


def test_firewall_fails_when_no_supported_backend_exists() -> None:
    # Given
    runner = FakeRunner()

    # When
    findings = FirewallAuditor(runner).audit()

    # Then
    assert findings[0].status is AuditStatus.FAIL


def test_firewall_flags_dangerous_listening_port() -> None:
    # Given
    runner = FakeRunner(
        available_commands={"ufw", "ss"},
        results={
            ("ufw", "status", "verbose"): CommandResult(
                0,
                "Status: active\nDefault: deny (incoming), allow (outgoing)",
                "",
            ),
            ("ss", "-lntH"): CommandResult(0, "LISTEN 0 128 0.0.0.0:23 0.0.0.0:*\n", ""),
        },
    )

    # When
    findings = FirewallAuditor(runner).audit()

    # Then
    assert any(
        finding.status is AuditStatus.FAIL and "23" in finding.details for finding in findings
    )
