<div align="center">

# 🛡️ Homelab Hardening Scanner

![Python](https://img.shields.io/badge/Python-3.11%2B-111820?style=for-the-badge&logo=python&logoColor=c9d1d9)
![Security](https://img.shields.io/badge/Security-SecOps-161b22?style=for-the-badge&logo=linux&logoColor=c9d1d9)
![Status](https://img.shields.io/badge/Status-Work_In_Progress-8b949e?style=for-the-badge)

*An automated SecOps auditing tool to verify the security posture of Linux servers.*

</div>

## 📌 Overview

**Homelab Hardening Scanner** is a read-only configuration auditor designed to assess the security baseline of Linux machines (such as Raspberry Pi home servers, VPS, or bare-metal setups). By applying Zero-Trust principles to local infrastructure, this tool programmatically inspects critical configuration files and reports compliance against strict security rules (Pass, Fail, or Warning).

This project was built to empirically demonstrate applied cybersecurity principles in an automated, programmatic way.

## 🚀 Core Features

- **🔒 SSH Posture Audit:** Inspects `/etc/ssh/sshd_config` to enforce strict access rules (e.g., `PermitRootLogin no`, `PasswordAuthentication no`, explicit allowed groups).
- **🧱 Firewall Validation:** Verifies that a firewall (such as `ufw` or `iptables`) is actively running with a default `DROP` policy for inbound connections.
- **👥 User & Privilege Audit:** Safely reads `/etc/shadow` to detect active accounts missing passwords, and maps out all users belonging to privileged groups (`sudo` or `wheel`).
- **📊 Multi-format Reporting:** Generates beautiful, human-readable terminal output using `rich`, and can export results to standard `JSON` or `Markdown` for programmatic ingestion or CI/CD pipelines.

## 🛠️ Tech Stack

- **Python 3.11+**
- **[Pydantic](https://docs.pydantic.dev/):** Used to define rigid, type-safe data models for security rules and compliance reports.
- **[Rich](https://rich.readthedocs.io/):** Powers the elegant, color-coded terminal user interface (TUI).
- **[uv](https://github.com/astral-sh/uv):** Provides strict and lightning-fast Python dependency management.

## 🏗️ Architecture & Modules

1. `ssh_auditor.py`: Parses the OpenSSH daemon configuration.
2. `firewall_auditor.py`: Queries firewall state and default policies.
3. `user_auditor.py`: Audits local authentication and privilege escalation vectors.
4. `reporter.py`: Aggregates the findings from all auditors into a structured compliance report.

## 🚧 Status

This project is currently in active development. The base architecture, dependency management (`pyproject.toml` / `uv.lock`), and module structure are initialized. Parsing logic and compliance engines are currently being implemented.
