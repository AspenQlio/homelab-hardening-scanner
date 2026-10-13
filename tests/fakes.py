from dataclasses import dataclass, field

from scanner.system import CommandResult


@dataclass(slots=True)
class FakeRunner:
    available_commands: set[str] = field(default_factory=set)
    results: dict[tuple[str, ...], CommandResult] = field(default_factory=dict)

    def available(self, command: str) -> bool:
        return command in self.available_commands

    def run(self, command: tuple[str, ...]) -> CommandResult:
        return self.results.get(command, CommandResult(returncode=1, stdout="", stderr="missing"))
