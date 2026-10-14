from pathlib import Path

from scanner.identity_auditor import IdentityAuditor
from scanner.models import AuditStatus


def test_identity_flags_system_account_with_password(tmp_path: Path) -> None:
    # Given
    passwd = tmp_path / "passwd"
    shadow = tmp_path / "shadow"
    groups = tmp_path / "group"
    sudoers = tmp_path / "sudoers"
    _ = passwd.write_text("root:x:0:0::/root:/bin/bash\nsvc:x:500:500::/srv:/bin/bash\n")
    _ = shadow.write_text("root:!:1::::::\nsvc:$6$hash:1::::::\n")
    _ = groups.write_text("sudo:x:27:aspen\ndocker:x:999:aspen\n")
    _ = sudoers.write_text("root ALL=(ALL:ALL) ALL\n")
    sudoers.chmod(0o440)

    # When
    findings = IdentityAuditor(passwd, shadow, groups, sudoers).audit()

    # Then
    assert any(
        finding.status is AuditStatus.FAIL and "svc" in finding.details for finding in findings
    )
