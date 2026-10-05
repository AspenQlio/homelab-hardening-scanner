# Homelab Hardening Scanner

> An automated SecOps auditing tool designed to verify the security posture of Linux servers against standard security baselines.

Homelab Hardening Scanner is a read-only configuration auditor for Linux machines (like a Raspberry Pi home server, VPS, or bare-metal setup). It inspects critical files and provides a clear report of what passes, what fails, and what needs attention to keep your homelab secure.

## Features

- **SSH Posture Audit:** Verifies strict access rules in `/etc/ssh/sshd_config` (e.g., `PermitRootLogin no`).
- **Firewall Validation:** Checks if a firewall (`ufw` or `iptables`) is active and dropping inbound traffic by default.
- **User & Privilege Audit:** Parses account databases to review `sudo` membership, interactive accounts, and `/etc/sudoers` permissions.
- **Docker Audit:** Reviews root-equivalent group access, privileged containers, and daemon port exposure.
- **System Health Audit:** Detects pending system updates and reboot markers.
- **Markdown Reporting:** Provides a clean terminal UI and exports portable audit reports.

## Architecture

The tool executes read-only checks across the local system. It relies on Python and Pydantic for strict data modeling and rule validation. The results are formatted using Rich for a terminal interface and can be exported as a Markdown file.

## Tech Stack

- **Language:** Python 3.11+
- **Data Modeling:** Pydantic
- **UI:** Rich
- **Package Manager:** uv

## Getting Started

### Prerequisites

- Python 3.11 or higher installed on the target machine.
- `uv` installed for dependency management.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AspenQlio/homelab-hardening-scanner.git
   cd homelab-hardening-scanner
   ```
2. **Sync dependencies:**
   ```bash
   uv sync
   ```

## Usage

Run the scanner to generate an audit report. Note that access to certain system files (like `/etc/shadow` or firewall states) may require elevated privileges.

```bash
uv run homelab-scanner scan --report audit.md
```

## License

This project is licensed under the MIT License.
