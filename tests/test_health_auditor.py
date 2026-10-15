from scanner.health_auditor import HealthAuditor
from scanner.models import AuditStatus
from scanner.system import CommandResult
from tests.fakes import FakeRunner


def test_health_warns_when_arch_updates_are_pending() -> None:
    # Given
    runner = FakeRunner(
        available_commands={"pacman"},
        results={("pacman", "-Qu"): CommandResult(0, "linux 6.1 -> 6.2\n", "")},
    )

    # When
    findings = HealthAuditor(runner, reboot_required=False).audit()

    # Then
    assert findings[0].status is AuditStatus.WARNING
