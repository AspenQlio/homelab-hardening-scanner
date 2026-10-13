"""Safe command execution boundary used by system auditors."""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Captured result from a command without shell interpretation."""

    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Capability required by auditors that inspect system commands."""

    def available(self, command: str) -> bool:
        """Reports whether an executable exists on PATH."""
        ...

    def run(self, command: tuple[str, ...]) -> CommandResult:
        """Executes an argument vector without invoking a shell."""
        ...


@dataclass(frozen=True, slots=True)
class SystemCommandRunner:
    """Subprocess adapter with bounded execution time."""

    timeout_seconds: float = 10.0

    def available(self, command: str) -> bool:
        """Reports whether an executable exists on PATH."""
        return shutil.which(command) is not None

    def run(self, command: tuple[str, ...]) -> CommandResult:
        """Executes an argument vector without invoking a shell."""
        completed = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=self.timeout_seconds,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
