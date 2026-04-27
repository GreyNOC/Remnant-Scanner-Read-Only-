# QA/QC Checklist

## Scope reviewed

- Desktop launch path
- Command-line scan path
- TXT and JSON report exports
- McAfee keyword and service-prefix matching
- Packaging scripts
- Read-only safety boundary

## Automated QA

Run from the repository root:

```cmd
scripts\run_qa.bat
```

The script performs:

1. Python syntax compilation for application and test files
2. Unit tests using the Python standard library test runner
3. CLI smoke test with TXT and JSON report output

## Manual Windows QA

Use an Administrator Command Prompt for complete coverage.

1. Run `python launch_gui.py`.
2. Confirm the GreyNOC header, GN badge, read-only badge, and footer render cleanly.
3. Click **Run Scan** and wait for completion.
4. Confirm findings are sorted by severity.
5. Double-click a finding and confirm the row details copy to the clipboard.
6. Save TXT and JSON reports and confirm filenames start with `greynoc_mcafee_remnant_report_`.
7. Run `python launch_gui.py --cli --txt reports\qa.txt --json reports\qa.json`.
8. Confirm both reports are created and contain the same finding count.
9. Build with `scripts\build_exe.bat`.
10. Run `dist\GreyNOC-McAfee-Remnant-Scanner.exe`.

## Safety QA

The scanner is read-only. The code path does not include delete operations, registry writes, service modification, driver removal, scheduled-task creation/deletion, network transmission, or telemetry.

## Known limits

- Some McAfee driver and service names use `mfe` prefixes. Prefix-only matches are classified as Medium because they can be false positives.
- Windows is the target operating system for full scan coverage. macOS and Linux checks are limited to common paths/process references.
- A clean report does not guarantee every possible remnant has been removed.
