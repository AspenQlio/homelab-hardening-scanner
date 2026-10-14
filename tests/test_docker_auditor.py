from scanner.docker_auditor import DockerAuditor
from scanner.models import AuditStatus
from scanner.system import CommandResult
from tests.fakes import FakeRunner


def test_docker_flags_privileged_container() -> None:
    # Given
    runner = FakeRunner(
        available_commands={"docker"},
        results={
            ("docker", "ps", "--quiet"): CommandResult(0, "abc\n", ""),
            (
                "docker",
                "inspect",
                "--format",
                "{{.Name}}|{{.HostConfig.Privileged}}",
                "abc",
            ): CommandResult(0, "/homeassistant|true\n", ""),
        },
    )

    # When
    findings = DockerAuditor(runner, docker_group_members=("aspen",), docker_host="").audit()

    # Then
    assert any(finding.status is AuditStatus.FAIL for finding in findings)
