# ⬛ Windows Event Log Extractor
### SOC Analysis & Incident Investigation Tool

A professional-grade, GUI-based Windows Event Log analysis tool designed for SOC analysts and incident responders. Built with Python and Tkinter for lightweight, dependency-minimal operation.

---

## 📋 Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Filter Presets](#filter-presets)
- [Supported Event IDs](#supported-event-ids)
- [Export Formats](#export-formats)
- [Building an Executable](#building-an-executable)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)

---

## ✨ Features

| Feature | Description |
|---|---|
| **Live Log Reading** | Security, System, Application logs via `win32evtlog` |
| **EVTX File Import** | Parse saved `.evtx` files (offline analysis) |
| **Multi-Filter Engine** | Filter by Event ID, keyword, time range, level |
| **Color-Coded Severity** | CRITICAL / HIGH / MEDIUM / INFO visual tiers |
| **Security Event Tagging** | 40+ tagged security-relevant Event IDs |
| **Built-in Investigation Presets** | One-click logon, persistence, privilege, and more |
| **Custom Filter Presets** | Save, load, and delete analyst-defined filters |
| **Quick Search** | Instant cross-column search bar |
| **Column Sorting** | Click any column header to sort |
| **Event Detail View** | Full message with extracted fields (CommandLine, IP, User, etc.) |
| **Right-Click Context** | Filter-by-field directly from any row |
| **Pagination** | 200 rows/page for large datasets |
| **Auto-Refresh** | Optional real-time refresh (configurable interval) |
| **Multi-Format Export** | CSV, JSON, TXT report |
| **Demo Mode** | Fully functional on non-Windows systems for training/dev |

---

## 🖥️ Requirements

### Minimum
- Python 3.8+
- Windows 10/11 or Windows Server 2016+
- Standard user account (limited logs) or **Administrator** (Security log)

### Python Packages

```
pip install pywin32          # Windows Event Log API (required on Windows)
pip install python-evtx      # Optional: enhanced EVTX file parsing
```

> **Note:** The tool runs in **Demo Mode** on Linux/macOS for training and development. All filtering, export, and UI features work with generated sample data.

---

## ⚙️ Installation

### Option 1: Run from Source

```bash
# Clone or download the project
cd soc_extractor

# Install dependencies
pip install pywin32
pip install python-evtx   # optional

# Launch
python main.py
```

### Option 2: Pre-built Executable (Windows)

Download `SOC_Extractor.exe` from releases and run directly. No Python required.

---

## 📖 Usage Guide

### 1. Select Log Source

Use the **Log Type** dropdown to choose:
- `Security` — Logon events, privilege use, audit policy (requires admin)
- `System` — Service changes, driver events, kernel events
- `Application` — Application crashes, errors, custom app logs

Set **Max Records** to control how many events to load (default: 5,000).

### 2. Load Logs

Click **⚡ LOAD LOGS** to begin reading. The status bar shows progress.

> For large logs, increase Max Records. Loading 50,000 events takes ~5–15 seconds.

### 3. Import EVTX File

Click **📂 Import EVTX File** to load a saved `.evtx` file from:
- `C:\Windows\System32\winevt\Logs\`
- A forensic image or collected artifact

### 4. Apply Filters

| Filter | How to Use |
|---|---|
| **Event ID(s)** | Enter IDs separated by commas: `4624,4625,4672` |
| **Keyword** | Matches any field — try `powershell`, `mimikatz`, `DOMAIN\user` |
| **Date/Time** | Use `YYYY-MM-DD HH:MM:SS` format, or click shortcut buttons (1h, 6h, 24h, 7d) |
| **Checkboxes** | OR-combined level filters: Errors, Warnings, Audit Success, Audit Failure |

Click **🔍 FILTER** to apply. The stats bar shows matching count.

### 5. Use Built-in Presets

The **Filter Presets** dropdown includes investigation-ready presets:

| Preset | Targets |
|---|---|
| Logon Activity | 4624, 4625, 4634, 4648, 4672, 4776 |
| Failed Logons | 4625, 4771, 4776 + Audit Failure |
| Privilege Escalation | 4672, 4673, 4674 |
| Process Creation | 4688 |
| Scheduled Tasks | 4698–4702 |
| Account Changes | 4720–4740 |
| Log Tampering | 1102, 1100, 1104 |
| New Services | 7045, 4697 |

### 6. Quick Search

Type in the **🔎 search bar** for instant filtering across all visible columns. Updates live as you type.

### 7. Examine Event Detail

- **Single-click** a row → populates the Event Detail tab
- **Double-click** a row → switches to the Detail tab automatically
- The detail view shows parsed sub-fields: CommandLine, Image, SourceIP, LogonType, etc.

### 8. Right-Click Context Menu

Right-click any row for quick actions:
- **Copy Row** — Tab-separated to clipboard
- **Copy Message** — Full event message to clipboard
- **Filter by Event ID** — Instantly filter to that Event ID
- **Filter by Computer** — Filter to that machine
- **Filter by User** — Filter to that user account

### 9. Export

Click **💾 EXPORT** to save the filtered result set:
- `.csv` — Structured data for Excel / SIEM import
- `.json` — Machine-readable for SOAR playbooks or Splunk
- `.txt` — Human-readable formatted report

### 10. Auto-Refresh

Enable **Auto-refresh** and set an interval (seconds) to poll live logs continuously. Useful during active incidents.

---

## 🔒 Privilege Requirements

| Log | Access Required |
|---|---|
| Security | Local Administrator or `SeSecurityPrivilege` |
| System | Standard user or Administrator |
| Application | Standard user or Administrator |

Run the tool as Administrator to access Security logs:
```
Right-click → Run as Administrator
```

---

## 🏷️ Supported Event IDs and Logic

### Authentication & Logon

| Event ID | Description | Severity |
|---|---|---|
| 4624 | Successful account logon | HIGH |
| 4625 | Failed account logon | HIGH |
| 4626 | User/Device claims information | MEDIUM |
| 4634 | Account logoff | INFO |
| 4648 | Logon with explicit credentials | HIGH |
| 4672 | Special privileges (admin logon) | HIGH |
| 4771 | Kerberos pre-authentication failed | HIGH |
| 4776 | NTLM credential validation | HIGH |

### Privilege & Access

| Event ID | Description | Severity |
|---|---|---|
| 4673 | Privileged service called | MEDIUM |
| 4674 | Operation on privileged object | MEDIUM |
| 4656 | Handle to object requested | MEDIUM |
| 4657 | Registry value modified | MEDIUM |
| 4660 | Object deleted | MEDIUM |
| 4663 | Object access attempted | MEDIUM |
| 4670 | Object permissions changed | MEDIUM |

### Process & Execution

| Event ID | Description | Severity |
|---|---|---|
| 4688 | New process created | HIGH |
| 4689 | Process exited | INFO |

### Persistence & Lateral Movement

| Event ID | Description | Severity |
|---|---|---|
| 4697 | Service installed in SCM | HIGH |
| 4698 | Scheduled task created | HIGH |
| 4699 | Scheduled task deleted | HIGH |
| 4700 | Scheduled task enabled | HIGH |
| 4701 | Scheduled task disabled | MEDIUM |
| 4702 | Scheduled task updated | MEDIUM |
| 7045 | New service installed (System log) | HIGH |

### Account Management

| Event ID | Description | Severity |
|---|---|---|
| 4720 | User account created | HIGH |
| 4722 | User account enabled | MEDIUM |
| 4723 | Password change attempt | MEDIUM |
| 4724 | Password reset attempt | MEDIUM |
| 4725 | User account disabled | MEDIUM |
| 4726 | User account deleted | HIGH |
| 4728 | Member added to global security group | HIGH |
| 4732 | Member added to local security group | HIGH |
| 4738 | User account changed | MEDIUM |
| 4740 | User account locked out | HIGH |
| 4756 | Member added to universal group | HIGH |

### Audit & Tampering

| Event ID | Description | Severity |
|---|---|---|
| 1100 | Event log service shutdown | CRITICAL |
| 1102 | Audit log cleared | CRITICAL |
| 1104 | Security log full | HIGH |
| 4719 | Audit policy changed | CRITICAL |

### System Events

| Event ID | Description | Severity |
|---|---|---|
| 7034 | Service crashed unexpectedly | MEDIUM |
| 7035 | Service control request sent | INFO |
| 7036 | Service state changed | INFO |
| 7040 | Service start type changed | MEDIUM |

---

## 📤 Export Formats

### CSV
- Columns: TimeCreated, EventID, Level, Severity, Tag, Computer, User, Source, LogName, CommandLine, Image, TargetUser, LogonType, SourceIP, ServiceName, TaskName, ShortMessage
- Encoding: UTF-8 with BOM (Excel-compatible)

### JSON
- Array of objects, one per event
- All fields including extracted sub-fields
- Pretty-printed with 2-space indent

### TXT Report
- Human-readable formatted report
- Full event messages included
- Suitable for email/ticket attachment

---

## 📦 Building an Executable

Install PyInstaller:
```bash
pip install pyinstaller
```

Build single-file executable:
```bash
pyinstaller --onefile --windowed --name SOC_Extractor main.py
```

The executable will appear in `dist/SOC_Extractor.exe`.

> **Note:** Ensure `pywin32` is installed before building. The executable will work on Windows without Python installed.

---

## 🏗️ Architecture

```
soc_extractor/
├── main.py              # Entry point
├── gui.py               # Tkinter UI, all user interaction
├── log_reader.py        # Windows Event Log + EVTX reading
├── parser.py            # Field normalization, severity scoring
├── filter_engine.py     # Filtering logic, preset persistence
├── exporter.py          # CSV / JSON / TXT output
├── filter_presets.json  # User-saved presets (auto-created)
└── README.md
```

### Module Responsibilities

| Module | Responsibility |
|---|---|
| `main.py` | Bootstrap: creates Tk root, launches app |
| `gui.py` | All UI layout, bindings, threading coordination |
| `log_reader.py` | `win32evtlog` / `python-evtx` / demo data |
| `parser.py` | Normalizes raw dicts, extracts sub-fields, assigns severity |
| `filter_engine.py` | Multi-criteria filtering, preset save/load |
| `exporter.py` | Format-specific writers |

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---|---|
| "Access Denied" reading Security log | Run as Administrator |
| `pywin32` not found | `pip install pywin32` then `python Scripts/pywin32_postinstall.py -install` |
| EVTX file shows no events | Try `pip install python-evtx` for enhanced parsing |
| UI freezes during load | Reduce Max Records; loading uses background threads |
| Empty Security log | Ensure auditing is enabled via `secpol.msc` → Local Policies → Audit Policy |

---

## 📄 License

MIT — Free for SOC, DFIR, and educational use.

---

*Built for speed of extraction, clarity of filtering, and usability under live incident pressure.*
