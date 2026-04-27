# GreyNOC McAfee Remnant Scanner

A GreyNOC-branded, read-only scanner for checking whether McAfee-related components remain on a Windows workstation after McAfee has been uninstalled.

The scanner reports evidence only. It does not delete files, edit registry keys, stop services, remove drivers, modify scheduled tasks, or transmit data.

## What it checks

- Installed-program registry entries
- Services and kernel drivers
- Scheduled tasks
- Startup registry entries
- Running processes
- Common McAfee application and data folders

## Repository layout

```text
.
|-- assets/                         # GreyNOC icon assets
|-- docs/                           # QA/QC and operating notes
|-- scripts/                        # Windows helper scripts
|-- src/greynoc_mcafee_scanner/     # Application code
|-- tests/                          # Unit tests
|-- launch_gui.py                   # Source-checkout launcher
|-- pyproject.toml                  # Python package metadata
`-- README.md
```

## Requirements

- Windows 10 or Windows 11 for full scan coverage
- Python 3.10 or newer
- Administrator Command Prompt or PowerShell for the most complete Windows results

The application uses only the Python standard library at runtime.

## Run the desktop app

```cmd
python launch_gui.py
```

## Run a command-line scan

```cmd
python launch_gui.py --cli
```

Write TXT and JSON reports:

```cmd
python launch_gui.py --cli --txt reports\mcafee_report.txt --json reports\mcafee_report.json
```

Return exit code 1 only when findings are present:

```cmd
python launch_gui.py --cli --fail-on-findings
```

## Build a Windows executable

```cmd
scripts\build_exe.bat
```

The executable is written to:

```text
dist\GreyNOC-McAfee-Remnant-Scanner.exe
```

## Run QA checks

```cmd
scripts\run_qa.bat
```

Manual QA steps are documented in [docs/QA_QC.md](docs/QA_QC.md).

## Safety posture

This is an audit utility. Exported reports can contain local paths, process names, service names, and registry locations from the scanned computer. Treat reports as internal operational artifacts.
