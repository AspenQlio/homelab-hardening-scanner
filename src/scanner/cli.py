from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .models import AuditStatus
from .ssh_auditor import SSHAuditor

def get_status_color(status: AuditStatus) -> str:
    if status == AuditStatus.PASS:
        return "[bold green]PASS[/bold green]"
    elif status == AuditStatus.FAIL:
        return "[bold red]FAIL[/bold red]"
    elif status == AuditStatus.WARNING:
        return "[bold yellow]WARN[/bold yellow]"
    return "[bold magenta]ERROR[/bold magenta]"

def main():
    console = Console()
    console.print(Panel.fit("[bold blue]Homelab Hardening Scanner[/bold blue]", border_style="blue"))
    
    with console.status("[bold cyan]Auditing system configuration...[/bold cyan]"):
        ssh = SSHAuditor()
        findings = ssh.audit()
    
    table = Table(title="Security Audit Results", show_header=True, header_style="bold magenta")
    table.add_column("Module", style="cyan", width=10)
    table.add_column("Check", style="white", width=25)
    table.add_column("Status", justify="center", width=10)
    table.add_column("Details", style="dim", width=40)
    
    fail_count = 0
    for finding in findings:
        table.add_row(
            finding.module,
            finding.check_name,
            get_status_color(finding.status),
            finding.details
        )
        if finding.status == AuditStatus.FAIL:
            fail_count += 1

    console.print(table)
    
    if fail_count > 0:
        console.print(f"\n[bold red]! Found {fail_count} critical security vulnerabilities. Review remediations.[/bold red]")
    else:
        console.print("\n[bold green]OK: System passes baseline security checks![/bold green]")

if __name__ == "__main__":
    main()
