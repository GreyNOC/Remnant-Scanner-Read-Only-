#!/usr/bin/env python3
"""GreyNOC McAfee Remnant Scanner.

The scanner is intentionally read-only. It reports evidence of McAfee remnants
without deleting files, modifying registry keys, stopping services, or changing
scheduled tasks.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception:  # pragma: no cover - only used when Tk is unavailable
    tk = None
    filedialog = None
    messagebox = None
    ttk = None

IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    try:
        import winreg  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - Windows only
        winreg = None  # type: ignore[assignment]
else:
    winreg = None  # type: ignore[assignment]


APP_NAME = "GreyNOC McAfee Remnant Scanner"
APP_SHORT_NAME = "McAfee Remnant Scanner"
APP_VERSION = "1.0.0"
APP_VENDOR = "GreyNOC"
APP_TAGLINE = "Post-uninstall audit utility"

BRAND_DARK = "#0B1F33"
BRAND_DARK_ALT = "#102A43"
BRAND_ACCENT = "#3B82F6"
BRAND_LIGHT = "#F4F7FB"
BRAND_TEXT = "#EAF2FF"
BRAND_MUTED = "#52606D"

KEYWORDS = (
    "mcafee",
    "mcafee.com",
    "mcafee llc",
    "mcafee, llc",
    "mcafee inc",
    "webadvisor",
    "safe connect",
    "livesafe",
    "total protection",
    "security scan plus",
)

SUSPECT_SERVICE_PREFIXES = (
    "mfe",
    "mfefire",
    "mfehid",
    "mfencrk",
    "mfencbdc",
    "mfemms",
    "mfewfpk",
    "mfewc",
    "mfeapfk",
    "mfetdi2k",
    "mfeavfk",
    "mfevtp",
)


@dataclass(frozen=True)
class Finding:
    """A single scanner finding."""

    category: str
    name: str
    location: str
    evidence: str
    severity: str = "Medium"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def resource_path(relative_path: str) -> Path:
    """Return a path that works from source, installed packages, and PyInstaller builds."""

    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / relative_path

    package_candidate = Path(__file__).resolve().parent / relative_path
    if package_candidate.exists():
        return package_candidate

    return Path(__file__).resolve().parents[2] / relative_path


def run_command(args: Sequence[str], timeout: int = 20) -> str:
    """Run a command safely and return combined stdout/stderr."""

    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            shell=False,
        )
    except Exception as exc:  # pragma: no cover - platform dependent
        return f"[command failed: {' '.join(args)}] {exc}"

    output = completed.stdout or ""
    if completed.stderr:
        output = f"{output}\n{completed.stderr}"
    return output


def text_contains_keyword(*parts: object) -> bool:
    """Return True when any known McAfee term is present."""

    joined = " ".join("" if part is None else str(part) for part in parts).lower()
    return any(keyword in joined for keyword in KEYWORDS)


def looks_like_mcafee_service(name: str, *evidence: object) -> bool:
    """Return True for known McAfee service evidence or common service prefixes."""

    lowered_name = (name or "").lower()
    if text_contains_keyword(name, *evidence):
        return True
    return any(lowered_name.startswith(prefix) for prefix in SUSPECT_SERVICE_PREFIXES)


def _registry_value(key: object, name: str) -> Optional[object]:
    if winreg is None:
        return None
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _registry_subkeys(root: object, path: str):
    if winreg is None:
        return
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    yield winreg.EnumKey(key, index)
                    index += 1
                except OSError:
                    break
    except OSError:
        return


def scan_installed_programs() -> list[Finding]:
    """Scan uninstall registry keys for McAfee product entries."""

    findings: list[Finding] = []
    if not IS_WINDOWS or winreg is None:
        return findings

    hives = (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    )
    uninstall_paths = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )

    for hive_name, hive in hives:
        for parent_path in uninstall_paths:
            for subkey in _registry_subkeys(hive, parent_path) or []:
                full_path = f"{parent_path}\\{subkey}"
                try:
                    with winreg.OpenKey(hive, full_path, 0, winreg.KEY_READ) as key:
                        values = {
                            "DisplayName": _registry_value(key, "DisplayName"),
                            "Publisher": _registry_value(key, "Publisher"),
                            "DisplayVersion": _registry_value(key, "DisplayVersion"),
                            "InstallLocation": _registry_value(key, "InstallLocation"),
                            "UninstallString": _registry_value(key, "UninstallString"),
                        }
                except OSError:
                    continue

                if text_contains_keyword(subkey, *values.values()):
                    display_name = values.get("DisplayName") or subkey
                    evidence = "; ".join(f"{key}={value}" for key, value in values.items() if value)
                    findings.append(
                        Finding(
                            category="Installed program",
                            name=str(display_name),
                            location=f"{hive_name}\\{full_path}",
                            evidence=evidence,
                            severity="High",
                        )
                    )
    return findings


def scan_services_and_drivers() -> list[Finding]:
    """Scan Windows service and driver registry entries."""

    findings: list[Finding] = []
    if not IS_WINDOWS or winreg is None:
        return findings

    base_path = r"SYSTEM\CurrentControlSet\Services"
    for subkey in _registry_subkeys(winreg.HKEY_LOCAL_MACHINE, base_path) or []:
        full_path = f"{base_path}\\{subkey}"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_path, 0, winreg.KEY_READ) as key:
                display_name = _registry_value(key, "DisplayName")
                image_path = _registry_value(key, "ImagePath")
                description = _registry_value(key, "Description")
                service_type = _registry_value(key, "Type")
                start_type = _registry_value(key, "Start")
        except OSError:
            continue

        if looks_like_mcafee_service(subkey, display_name, image_path, description):
            strong = text_contains_keyword(subkey, display_name, image_path, description)
            evidence = (
                f"DisplayName={display_name}; ImagePath={image_path}; "
                f"Description={description}; Type={service_type}; Start={start_type}"
            )
            findings.append(
                Finding(
                    category="Service/driver",
                    name=str(display_name or subkey),
                    location=f"HKLM\\{full_path}",
                    evidence=evidence,
                    severity="High" if strong else "Medium",
                )
            )
    return findings


def scan_scheduled_tasks() -> list[Finding]:
    """Scan Windows scheduled tasks for McAfee references."""

    findings: list[Finding] = []
    if not IS_WINDOWS:
        return findings

    output = run_command(["schtasks", "/Query", "/FO", "CSV", "/V"], timeout=45)
    if not output.strip() or output.lower().startswith("[command failed"):
        return findings

    try:
        rows = list(csv.DictReader(output.splitlines()))
    except Exception:
        rows = []

    for row in rows:
        combined = " ".join(str(value) for value in row.values())
        if text_contains_keyword(combined):
            task_name = row.get("TaskName") or row.get("Task Name") or "McAfee-related scheduled task"
            task_to_run = row.get("Task To Run") or row.get("Task To Run ") or ""
            status = row.get("Status") or ""
            findings.append(
                Finding(
                    category="Scheduled task",
                    name=task_name,
                    location=task_to_run or "Task Scheduler",
                    evidence=f"Status={status}; Task={task_to_run}",
                    severity="Medium",
                )
            )
    return findings


def scan_startup_registry() -> list[Finding]:
    """Scan Windows startup registry values."""

    findings: list[Finding] = []
    if not IS_WINDOWS or winreg is None:
        return findings

    hives = (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    )
    run_paths = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    )

    for hive_name, hive in hives:
        for run_path in run_paths:
            try:
                with winreg.OpenKey(hive, run_path, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _value_type = winreg.EnumValue(key, index)
                            index += 1
                        except OSError:
                            break
                        if text_contains_keyword(name, value):
                            findings.append(
                                Finding(
                                    category="Startup entry",
                                    name=str(name),
                                    location=f"{hive_name}\\{run_path}",
                                    evidence=str(value),
                                    severity="Medium",
                                )
                            )
            except OSError:
                continue
    return findings


def scan_running_processes() -> list[Finding]:
    """Scan running processes for McAfee references."""

    findings: list[Finding] = []
    system_name = platform.system().lower()

    if system_name == "windows":
        output = run_command(["tasklist", "/FO", "CSV", "/V"], timeout=20)
        try:
            rows = list(csv.DictReader(output.splitlines()))
        except Exception:
            rows = []

        for row in rows:
            combined = " ".join(str(value) for value in row.values())
            process_name = row.get("Image Name") or row.get("ImageName") or "Process"
            if text_contains_keyword(combined) or looks_like_mcafee_service(str(process_name)):
                findings.append(
                    Finding(
                        category="Running process",
                        name=str(process_name),
                        location=f"PID {row.get('PID', '')}",
                        evidence=combined,
                        severity="High",
                    )
                )
    else:
        output = run_command(["ps", "aux"], timeout=20)
        for line in output.splitlines():
            if text_contains_keyword(line):
                parts = line.split(None, 10)
                process_name = parts[10] if len(parts) > 10 else line
                findings.append(
                    Finding(
                        category="Running process",
                        name=process_name[:140],
                        location="ps aux",
                        evidence=line[:1000],
                        severity="High",
                    )
                )
    return findings


def _existing_paths(paths: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        try:
            if not path.exists():
                continue

            is_dir = path.is_dir()
            detail = ""
            if is_dir:
                try:
                    detail = f"; immediate children={sum(1 for _ in path.iterdir())}"
                except Exception:
                    detail = "; immediate children=unknown"

            findings.append(
                Finding(
                    category="Folder/file",
                    name=path.name or str(path),
                    location=str(path),
                    evidence=f"Exists; type={'directory' if is_dir else 'file'}{detail}",
                    severity="Medium",
                )
            )
        except Exception:
            continue
    return findings


def scan_common_paths() -> list[Finding]:
    """Scan common filesystem locations for McAfee remnants."""

    findings: list[Finding] = []
    system_name = platform.system().lower()

    if system_name == "windows":
        candidates = (
            r"%ProgramFiles%\McAfee",
            r"%ProgramFiles%\Common Files\McAfee",
            r"%ProgramFiles(x86)%\McAfee",
            r"%ProgramFiles(x86)%\Common Files\McAfee",
            r"%ProgramData%\McAfee",
            r"%ProgramData%\McAfee.com",
            r"%LocalAppData%\McAfee",
            r"%AppData%\McAfee",
            r"%CommonProgramFiles%\McAfee",
            r"%CommonProgramFiles(x86)%\McAfee",
            r"%ProgramFiles%\McAfee.com",
            r"%ProgramFiles(x86)%\McAfee.com",
            r"%ProgramFiles%\McAfee Security Scan",
            r"%ProgramFiles(x86)%\McAfee Security Scan",
            r"%ProgramFiles%\McAfee WebAdvisor",
            r"%ProgramFiles(x86)%\McAfee WebAdvisor",
        )
        findings.extend(_existing_paths(Path(os.path.expandvars(path)) for path in candidates))

        for root_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LocalAppData", "AppData"):
            root_value = os.environ.get(root_var)
            if not root_value:
                continue
            try:
                for child in Path(root_value).iterdir():
                    if text_contains_keyword(child.name):
                        findings.extend(_existing_paths([child]))
            except Exception:
                continue

    elif system_name == "darwin":
        candidates = (
            Path("/Applications/McAfee Endpoint Security for Mac.app"),
            Path("/Applications/McAfee AntiVirus.app"),
            Path("/Library/Application Support/McAfee"),
            Path.home() / "Library/Application Support/McAfee",
        )
        findings.extend(_existing_paths(candidates))
        for root in (Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"), Path("/Library/Extensions")):
            try:
                for child in root.iterdir():
                    if text_contains_keyword(child.name):
                        findings.extend(_existing_paths([child]))
            except Exception:
                continue

    else:
        candidates = (
            Path("/opt/McAfee"),
            Path("/opt/McAfee/ens"),
            Path("/var/McAfee"),
            Path("/etc/ma.d"),
        )
        findings.extend(_existing_paths(candidates))

    return findings


def scan_system() -> list[Finding]:
    """Run all scanners and return de-duplicated findings."""

    all_findings: list[Finding] = []
    scanners = (
        scan_installed_programs,
        scan_services_and_drivers,
        scan_scheduled_tasks,
        scan_startup_registry,
        scan_running_processes,
        scan_common_paths,
    )

    for scanner in scanners:
        try:
            all_findings.extend(scanner())
        except Exception as exc:  # pragma: no cover - defensive guard
            all_findings.append(
                Finding(
                    category="Scanner warning",
                    name=scanner.__name__,
                    location="Scanner",
                    evidence=str(exc),
                    severity="Low",
                )
            )

    seen: set[tuple[str, str, str, str]] = set()
    unique_findings: list[Finding] = []
    for finding in all_findings:
        key = (finding.category, finding.name, finding.location, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)
    return unique_findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Return counts by severity."""

    return {
        "High": sum(1 for finding in findings if finding.severity == "High"),
        "Medium": sum(1 for finding in findings if finding.severity == "Medium"),
        "Low": sum(1 for finding in findings if finding.severity == "Low"),
    }


def render_text_report(findings: list[Finding]) -> str:
    """Build a plain-text report suitable for ticket attachments."""

    counts = severity_counts(findings)
    lines = [
        f"{APP_NAME} Report",
        f"Version: {APP_VERSION}",
        f"Purpose: {APP_TAGLINE}",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Computer: {platform.node()}",
        f"OS: {platform.platform()}",
        "",
        f"Total findings: {len(findings)}",
        f"High: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']}",
        "",
    ]

    if not findings:
        lines.extend(
            [
                "Result: No McAfee-related remnants were found by this scanner.",
                "Note: A clean report does not guarantee every possible remnant has been removed.",
            ]
        )
        return "\n".join(lines)

    severity_rank = {"High": 0, "Medium": 1, "Low": 2}
    ordered_findings = sorted(findings, key=lambda item: (severity_rank.get(item.severity, 9), item.category, item.name))
    for index, finding in enumerate(ordered_findings, start=1):
        lines.extend(
            [
                f"{index}. [{finding.severity}] {finding.category}: {finding.name}",
                f"   Location: {finding.location}",
                f"   Evidence: {finding.evidence}",
                "",
            ]
        )

    lines.extend(
        [
            "Operator notes:",
            "- The scanner is read-only and did not remove or change anything.",
            "- Medium findings should be reviewed before remediation because prefix-based service matches can be false positives.",
            "- Use approved removal tooling or administrative procedures for remediation.",
        ]
    )
    return "\n".join(lines)


def build_json_payload(findings: list[Finding]) -> dict[str, object]:
    """Return a structured report payload."""

    return {
        "application": APP_NAME,
        "version": APP_VERSION,
        "purpose": APP_TAGLINE,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "computer": platform.node(),
        "os": platform.platform(),
        "total_findings": len(findings),
        "severity_counts": severity_counts(findings),
        "findings": [finding.to_dict() for finding in findings],
    }


def _ensure_parent(path: Path) -> None:
    path.expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def save_text_report(findings: list[Finding], path: Path) -> None:
    _ensure_parent(path)
    path.write_text(render_text_report(findings), encoding="utf-8")


def save_json_report(findings: list[Finding], path: Path) -> None:
    _ensure_parent(path)
    path.write_text(json.dumps(build_json_payload(findings), indent=2), encoding="utf-8")


def default_report_name(suffix: str) -> str:
    return f"greynoc_mcafee_remnant_report_{time.strftime('%Y%m%d_%H%M%S')}.{suffix}"


class ScannerApp:
    """GreyNOC-branded desktop scanner."""

    def __init__(self, root: "tk.Tk") -> None:
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1180x720")
        self.root.minsize(980, 620)
        self.root.configure(bg=BRAND_LIGHT)

        self.findings: list[Finding] = []
        self.scan_thread: Optional[threading.Thread] = None
        self.summary_var = tk.StringVar(value="Ready to scan for McAfee remnants.")
        self.status_var = tk.StringVar(value="Read-only scanner. No files, services, drivers, tasks, or registry keys will be changed.")

        self._set_window_icon()
        self._configure_style()
        self._build_menu()
        self._build_header()
        self._build_actions()
        self._build_results_table()
        self._build_footer()

    def _set_window_icon(self) -> None:
        try:
            icon_path = resource_path("assets/greynoc_icon.png")
            if icon_path.exists():
                self._icon_image = tk.PhotoImage(file=str(icon_path))
                self.root.iconphoto(True, self._icon_image)
        except Exception:
            pass

    def _configure_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Card.TFrame", background="white")
        style.configure("Card.TLabel", background="white", foreground="#243B53")
        style.configure("Footer.TLabel", background=BRAND_LIGHT, foreground=BRAND_MUTED)
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=(12, 7))
        style.map(
            "Accent.TButton",
            background=[("active", BRAND_DARK_ALT), ("!disabled", BRAND_ACCENT)],
            foreground=[("!disabled", "white")],
        )
        style.configure("Treeview", rowheight=28, fieldbackground="white", background="white", font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Run Scan", command=self.start_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Save TXT Report", command=self.save_txt)
        file_menu.add_command(label="Save JSON Report", command=self.save_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.destroy)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About", command=self.show_about)

        menu.add_cascade(label="File", menu=file_menu)
        menu.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menu)

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=BRAND_DARK, height=110)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        logo = tk.Canvas(header, width=68, height=68, bg=BRAND_DARK, highlightthickness=0)
        logo.pack(side=tk.LEFT, padx=(18, 12), pady=20)
        logo.create_oval(4, 4, 64, 64, fill=BRAND_ACCENT, outline="#79B4FF", width=2)
        logo.create_text(34, 34, text="GN", fill="white", font=("Segoe UI", 18, "bold"))

        title_area = tk.Frame(header, bg=BRAND_DARK)
        title_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, pady=20)
        tk.Label(title_area, text=APP_VENDOR, bg=BRAND_DARK, fg=BRAND_TEXT, font=("Segoe UI", 22, "bold")).pack(anchor=tk.W)
        tk.Label(title_area, text=APP_SHORT_NAME, bg=BRAND_DARK, fg="#BFD7FF", font=("Segoe UI", 13)).pack(anchor=tk.W)
        tk.Label(title_area, text=APP_TAGLINE, bg=BRAND_DARK, fg="#D9E8FF", font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(4, 0))

        badge = tk.Frame(header, bg=BRAND_DARK_ALT, padx=14, pady=9)
        badge.pack(side=tk.RIGHT, padx=18, pady=28)
        tk.Label(badge, text="READ-ONLY", bg=BRAND_DARK_ALT, fg="white", font=("Segoe UI", 10, "bold")).pack()
        tk.Label(badge, text="Audit mode", bg=BRAND_DARK_ALT, fg="#BFD7FF", font=("Segoe UI", 8)).pack()

    def _build_actions(self) -> None:
        card = ttk.Frame(self.root, style="Card.TFrame", padding=(16, 13))
        card.pack(fill=tk.X, padx=16, pady=(16, 10))

        left = ttk.Frame(card, style="Card.TFrame")
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(
            left,
            text="Scans installed programs, services and drivers, scheduled tasks, startup entries, running processes, and common folders.",
            style="Card.TLabel",
            font=("Segoe UI", 10),
        ).pack(anchor=tk.W)
        ttk.Label(left, textvariable=self.summary_var, style="Card.TLabel", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(8, 0))
        ttk.Label(left, textvariable=self.status_var, style="Card.TLabel").pack(anchor=tk.W, pady=(2, 0))

        right = ttk.Frame(card, style="Card.TFrame")
        right.pack(side=tk.RIGHT, padx=(12, 0))
        self.scan_button = ttk.Button(right, text="Run Scan", command=self.start_scan, style="Accent.TButton")
        self.scan_button.pack(side=tk.LEFT)
        self.save_txt_button = ttk.Button(right, text="Save TXT", command=self.save_txt, state=tk.DISABLED)
        self.save_txt_button.pack(side=tk.LEFT, padx=(8, 0))
        self.save_json_button = ttk.Button(right, text="Save JSON", command=self.save_json, state=tk.DISABLED)
        self.save_json_button.pack(side=tk.LEFT, padx=(8, 0))

    def _build_results_table(self) -> None:
        table_frame = ttk.Frame(self.root, padding=(16, 0))
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("severity", "category", "name", "location", "evidence")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        headings = {"severity": "Severity", "category": "Category", "name": "Name", "location": "Location", "evidence": "Evidence"}
        widths = {"severity": 85, "category": 150, "name": 245, "location": 360, "evidence": 560}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor=tk.W, stretch=True)

        self.tree.tag_configure("High", background="#FFF1F0")
        self.tree.tag_configure("Medium", background="#FFF8E1")
        self.tree.tag_configure("Low", background="#F0F6FF")

        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self.copy_selected_finding)

    def _build_footer(self) -> None:
        footer = tk.Frame(self.root, bg=BRAND_LIGHT)
        footer.pack(fill=tk.X, padx=16, pady=(6, 12))
        ttk.Label(
            footer,
            text="GreyNOC security operations support utility | Double-click a row to copy finding details",
            style="Footer.TLabel",
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT)
        ttk.Button(footer, text="Exit", command=self.root.destroy).pack(side=tk.RIGHT)

    def start_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.scan_button.configure(state=tk.DISABLED)
        self.save_txt_button.configure(state=tk.DISABLED)
        self.save_json_button.configure(state=tk.DISABLED)
        self.summary_var.set("Scanning...")
        self.status_var.set("Run as Administrator for the most complete Windows results.")
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        self.scan_thread.start()
        self.root.after(200, self._poll_scan)

    def _scan_worker(self) -> None:
        self.findings = scan_system()

    def _poll_scan(self) -> None:
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(200, self._poll_scan)
            return
        self._populate_results()
        self.scan_button.configure(state=tk.NORMAL)
        self.save_txt_button.configure(state=tk.NORMAL)
        self.save_json_button.configure(state=tk.NORMAL)

    def _populate_results(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)

        severity_rank = {"High": 0, "Medium": 1, "Low": 2}
        ordered_findings = sorted(self.findings, key=lambda item: (severity_rank.get(item.severity, 9), item.category, item.name))
        for finding in ordered_findings:
            self.tree.insert(
                "",
                tk.END,
                values=(finding.severity, finding.category, finding.name, finding.location, finding.evidence),
                tags=(finding.severity,),
            )

        counts = severity_counts(self.findings)
        if not self.findings:
            self.summary_var.set("Scan complete: no McAfee-related remnants found.")
            self.status_var.set("No changes were made. Export the report if a record is needed.")
            return

        self.summary_var.set(
            f"Scan complete: {len(self.findings)} finding(s). High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}."
        )
        self.status_var.set("Review findings before remediation. This scanner does not remove anything.")

    def _confirm_empty_report_save(self) -> bool:
        if self.findings:
            return True
        return messagebox.askyesno("Save empty report?", "No findings are currently loaded. Save an empty report anyway?")

    def save_txt(self) -> None:
        if not self._confirm_empty_report_save():
            return
        path = filedialog.asksaveasfilename(
            title="Save TXT report",
            defaultextension=".txt",
            initialfile=default_report_name("txt"),
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        save_text_report(self.findings, Path(path))
        messagebox.showinfo("Report saved", f"Report saved:\n{path}")

    def save_json(self) -> None:
        if not self._confirm_empty_report_save():
            return
        path = filedialog.asksaveasfilename(
            title="Save JSON report",
            defaultextension=".json",
            initialfile=default_report_name("json"),
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        save_json_report(self.findings, Path(path))
        messagebox.showinfo("Report saved", f"Report saved:\n{path}")

    def copy_selected_finding(self, _event: object | None = None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        values = self.tree.item(selected[0], "values")
        if not values:
            return
        text = (
            f"Severity: {values[0]}\n"
            f"Category: {values[1]}\n"
            f"Name: {values[2]}\n"
            f"Location: {values[3]}\n"
            f"Evidence: {values[4]}"
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Selected finding copied to clipboard.")

    def show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{APP_NAME}\nVersion {APP_VERSION}\n\n{APP_TAGLINE}\n\nRead-only GreyNOC audit utility.",
        )


def run_gui() -> int:
    if tk is None:
        print("Tkinter is unavailable. Run with --cli.", file=sys.stderr)
        return 2
    root = tk.Tk()
    ScannerApp(root)
    root.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GreyNOC read-only scanner for McAfee remnants.")
    parser.add_argument("--cli", action="store_true", help="Run in command-line mode instead of launching the desktop UI.")
    parser.add_argument("--txt", type=Path, help="Write a plain-text report to this path.")
    parser.add_argument("--json", type=Path, help="Write a JSON report to this path.")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 1 when findings are present. Default exit code is 0 when the scan completes.",
    )
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = scan_system()
    if args.txt:
        save_text_report(findings, args.txt)
    if args.json:
        save_json_report(findings, args.json)

    print(render_text_report(findings))
    if args.fail_on_findings and findings:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--cli" in args or "--txt" in args or "--json" in args or "--fail-on-findings" in args:
        return run_cli(args)
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
