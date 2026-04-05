"""
log_reader.py - Windows Event Log Collection Module
Handles reading from live Windows logs and EVTX files
"""

import sys
import os
import datetime
from typing import List, Dict, Optional, Callable
import threading

# ── Platform detection ──────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import win32security
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
else:
    WIN32_AVAILABLE = False

# Optional evtx library (cross-platform EVTX parsing)
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_LIB_AVAILABLE = True
except ImportError:
    EVTX_LIB_AVAILABLE = False

# Optional xml parsing (always available)
import xml.etree.ElementTree as ET


# ── Known Log Sources ───────────────────────────────────────────────────────
LOG_SOURCES = ["Security", "System", "Application"]

# ── Security-relevant Event ID tags ────────────────────────────────────────
SECURITY_EVENT_TAGS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4626: "User/Device Claims",
    4627: "Group Membership",
    4634: "Logoff",
    4648: "Explicit Credential Logon",
    4656: "Object Handle Requested",
    4657: "Registry Value Modified",
    4660: "Object Deleted",
    4661: "SAM Object Handle",
    4662: "Directory Service Object",
    4663: "Object Access Attempt",
    4670: "Permissions Changed",
    4672: "Privileged Logon (Special Logon)",
    4673: "Privileged Service Called",
    4688: "Process Creation",
    4689: "Process Exit",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4699: "Scheduled Task Deleted",
    4700: "Scheduled Task Enabled",
    4701: "Scheduled Task Disabled",
    4702: "Scheduled Task Updated",
    4719: "Audit Policy Changed",
    4720: "User Account Created",
    4722: "User Account Enabled",
    4723: "Password Change Attempt",
    4724: "Password Reset Attempt",
    4725: "User Account Disabled",
    4726: "User Account Deleted",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4738: "User Account Changed",
    4740: "User Account Locked Out",
    4756: "Member Added to Universal Group",
    4771: "Kerberos Pre-Auth Failed",
    4776: "NTLM Auth Attempt",
    4798: "User Local Group Enum",
    4799: "Security Group Enum",
    1100: "Event Log Service Shutdown",
    1102: "Audit Log Cleared",
    1104: "Security Log Full",
    # System events
    7034: "Service Crashed",
    7035: "Service Control Sent",
    7036: "Service State Changed",
    7040: "Service Start Type Changed",
    7045: "New Service Installed",
    # Application events
    1000: "Application Error",
    1001: "Windows Error Reporting",
}

# Severity buckets for colour-coding
CRITICAL_IDS  = {1102, 4625, 4648, 4697, 4698, 7045, 4719, 4720, 4726, 4740, 4771}
HIGH_IDS      = {4624, 4672, 4688, 4698, 4699, 4700, 4701, 4702, 4756, 4728, 4732, 4776}
MEDIUM_IDS    = {4656, 4657, 4660, 4661, 4662, 4663, 4670, 4689, 4722, 4723, 4724, 4725, 4738}

# ── Raw record type ─────────────────────────────────────────────────────────
RawEvent = Dict


class EventLogReader:
    """
    Unified reader for live Windows event logs and EVTX files.
    Uses win32evtlog when available; falls back to demo / evtx-lib parsing.
    """

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.progress_cb = progress_cb or (lambda msg, pct: None)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def reset(self):
        self._stop_event.clear()

    # ── Public API ──────────────────────────────────────────────────────────

    def read_live(
        self,
        log_name: str = "Security",
        max_records: int = 5000,
    ) -> List[RawEvent]:
        """Read events from a live Windows log source."""
        self.reset()
        if WIN32_AVAILABLE:
            return self._read_win32(log_name, max_records)
        else:
            return self._generate_demo_events(log_name, max_records)

    def read_evtx(self, file_path: str, max_records: int = 10000) -> List[RawEvent]:
        """Read events from an .evtx file."""
        self.reset()
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        if EVTX_LIB_AVAILABLE:
            return self._read_evtx_lib(file_path, max_records)
        else:
            # Fallback: try win32evtlog OpenBackupEventLog
            if WIN32_AVAILABLE:
                return self._read_win32_backup(file_path, max_records)
            else:
                return self._generate_demo_events("EVTX", max_records, file_hint=file_path)

    # ── win32evtlog implementation ──────────────────────────────────────────

    def _read_win32(self, log_name: str, max_records: int) -> List[RawEvent]:
        events: List[RawEvent] = []
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            read = 0

            self.progress_cb(f"Reading {log_name} ({total:,} records)…", 0)

            while not self._stop_event.is_set():
                raw = win32evtlog.ReadEventLog(hand, flags, 0)
                if not raw:
                    break
                for ev in raw:
                    if self._stop_event.is_set():
                        break
                    events.append(self._parse_win32_event(ev, log_name))
                    read += 1
                    if read >= max_records:
                        break
                    if read % 500 == 0:
                        pct = min(int(read / max_records * 100), 99)
                        self.progress_cb(f"Loaded {read:,} events…", pct)

                if read >= max_records:
                    break

            win32evtlog.CloseEventLog(hand)
            self.progress_cb(f"Done — {len(events):,} events loaded.", 100)

        except Exception as exc:
            self.progress_cb(f"Error reading {log_name}: {exc}", -1)
            raise

        return events

    def _read_win32_backup(self, file_path: str, max_records: int) -> List[RawEvent]:
        events: List[RawEvent] = []
        try:
            hand = win32evtlog.OpenBackupEventLog(None, file_path)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            read = 0
            self.progress_cb(f"Reading EVTX backup: {os.path.basename(file_path)}…", 0)

            while not self._stop_event.is_set():
                raw = win32evtlog.ReadEventLog(hand, flags, 0)
                if not raw:
                    break
                for ev in raw:
                    events.append(self._parse_win32_event(ev, "EVTX"))
                    read += 1
                    if read >= max_records:
                        break
                    if read % 500 == 0:
                        self.progress_cb(f"Loaded {read:,} events…", min(int(read / max_records * 100), 99))
                if read >= max_records:
                    break

            win32evtlog.CloseEventLog(hand)
            self.progress_cb(f"Done — {len(events):,} events loaded.", 100)
        except Exception as exc:
            self.progress_cb(f"Error reading EVTX: {exc}", -1)
            raise
        return events

    def _parse_win32_event(self, ev, log_name: str) -> RawEvent:
        try:
            msg = win32evtlogutil.SafeFormatMessage(ev, log_name)
        except Exception:
            msg = " ".join(ev.StringInserts) if ev.StringInserts else ""

        event_id = ev.EventID & 0xFFFF  # mask to 16-bit
        time_obj = ev.TimeGenerated
        if hasattr(time_obj, "Format"):
            # pywintypes datetime
            try:
                time_str = time_obj.strftime("%Y-%m-%d %H:%M:%S")
                time_dt = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                time_str = str(time_obj)
                time_dt = None
        else:
            time_str = str(time_obj)
            time_dt = None

        level_map = {
            win32con.EVENTLOG_ERROR_TYPE: "Error",
            win32con.EVENTLOG_WARNING_TYPE: "Warning",
            win32con.EVENTLOG_INFORMATION_TYPE: "Information",
            win32con.EVENTLOG_AUDIT_SUCCESS: "Audit Success",
            win32con.EVENTLOG_AUDIT_FAILURE: "Audit Failure",
        }
        level = level_map.get(ev.EventType, "Unknown")

        return {
            "TimeCreated": time_str,
            "_datetime": time_dt,
            "EventID": event_id,
            "Level": level,
            "Source": ev.SourceName or "",
            "Computer": ev.ComputerName or "",
            "User": self._sid_to_name(ev.Sid),
            "Message": msg.strip() if msg else "",
            "LogName": log_name,
            "Tag": SECURITY_EVENT_TAGS.get(event_id, ""),
        }

    def _sid_to_name(self, sid) -> str:
        if sid is None:
            return ""
        try:
            name, domain, _ = win32security.LookupAccountSid(None, sid)
            return f"{domain}\\{name}" if domain else name
        except Exception:
            return str(sid)

    # ── evtx library implementation ─────────────────────────────────────────

    def _read_evtx_lib(self, file_path: str, max_records: int) -> List[RawEvent]:
        events: List[RawEvent] = []
        read = 0
        self.progress_cb(f"Parsing EVTX: {os.path.basename(file_path)}…", 0)
        try:
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    if self._stop_event.is_set():
                        break
                    try:
                        xml_str = record.xml()
                        ev = self._parse_evtx_xml(xml_str)
                        if ev:
                            events.append(ev)
                    except Exception:
                        pass
                    read += 1
                    if read >= max_records:
                        break
                    if read % 500 == 0:
                        self.progress_cb(f"Parsed {read:,} records…", min(int(read / max_records * 100), 99))
        except Exception as exc:
            self.progress_cb(f"EVTX parse error: {exc}", -1)
            raise
        self.progress_cb(f"Done — {len(events):,} events loaded.", 100)
        return events

    def _parse_evtx_xml(self, xml_str: str) -> Optional[RawEvent]:
        try:
            root = ET.fromstring(xml_str)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            sys_el = root.find("e:System", ns)
            if sys_el is None:
                return None

            def sys_text(tag):
                el = sys_el.find(f"e:{tag}", ns)
                return el.text if el is not None else ""

            def sys_attr(tag, attr):
                el = sys_el.find(f"e:{tag}", ns)
                return el.get(attr, "") if el is not None else ""

            event_id = int(sys_text("EventID") or 0)
            time_str = sys_attr("TimeCreated", "SystemTime") or ""
            # Normalise ISO timestamp
            time_dt = None
            if time_str:
                try:
                    time_str_clean = time_str[:19].replace("T", " ")
                    time_dt = datetime.datetime.strptime(time_str_clean, "%Y-%m-%d %H:%M:%S")
                    time_str = time_str_clean
                except Exception:
                    pass

            level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "0": "Audit"}
            level_code = sys_attr("Level", "") or "0"
            level = level_map.get(level_code, "Unknown")

            # Determine audit success/failure from Keywords
            keywords_hex = sys_attr("Keywords", "")
            try:
                kw_int = int(keywords_hex, 16) if keywords_hex.startswith("0x") else int(keywords_hex or "0", 16)
                if kw_int & 0x8020000000000000:
                    level = "Audit Success"
                elif kw_int & 0x8010000000000000:
                    level = "Audit Failure"
            except Exception:
                pass

            computer = sys_text("Computer")
            provider = sys_attr("Provider", "Name")

            # Security -> User SID
            security_el = sys_el.find("e:Security", ns)
            user_sid = security_el.get("UserID", "") if security_el is not None else ""

            # EventData / UserData message assembly
            msg_parts = []
            event_data = root.find("e:EventData", ns)
            if event_data is not None:
                for data in event_data:
                    name = data.get("Name", "")
                    val = data.text or ""
                    if name:
                        msg_parts.append(f"{name}: {val}")
                    elif val:
                        msg_parts.append(val)
            message = "\n".join(msg_parts)

            return {
                "TimeCreated": time_str,
                "_datetime": time_dt,
                "EventID": event_id,
                "Level": level,
                "Source": provider,
                "Computer": computer,
                "User": user_sid,
                "Message": message,
                "LogName": "EVTX",
                "Tag": SECURITY_EVENT_TAGS.get(event_id, ""),
            }
        except Exception:
            return None

    # ── Demo / fallback event generator ────────────────────────────────────

    def _generate_demo_events(
        self, log_name: str, max_records: int = 200, file_hint: str = ""
    ) -> List[RawEvent]:
        """
        Generate realistic-looking demo events for non-Windows environments.
        This lets analysts preview the UI on Linux/macOS.
        """
        import random

        self.progress_cb("Demo mode — generating sample events…", 0)

        computers = ["WORKSTATION-01", "DC-SERVER", "ANALYST-PC", "SRV-WEBAPP", "SRV-DB"]
        users = ["DOMAIN\\jsmith", "DOMAIN\\aadmin", "SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "DOMAIN\\svc_backup"]
        ips = ["192.168.1.10", "10.0.0.5", "172.16.0.22", "10.10.1.99"]

        def fake_msg(eid, user, computer, ip):
            templates = {
                4624: f"An account was successfully logged on.\nSubject: SYSTEM\nLogon Account: {user}\nSource IP: {ip}\nLogon Type: 3",
                4625: f"An account failed to log on.\nAccount Name: {user}\nSource IP: {ip}\nFailure Reason: Unknown user name or bad password.",
                4672: f"Special privileges assigned to new logon.\nAccount Name: {user}\nPrivileges: SeDebugPrivilege, SeBackupPrivilege",
                4688: f"A new process was created.\nCreator: {user}\nNew Process: C:\\Windows\\System32\\cmd.exe\nCommand Line: cmd.exe /c whoami",
                4698: f"A scheduled task was created.\nTask Name: \\Microsoft\\Windows\\UpdateCheck\nCreated By: {user}",
                1102: f"The audit log was cleared.\nSubject Account Name: {user}\nSubject Domain: DOMAIN",
                7045: f"A new service was installed.\nService Name: SuspiciousSvc\nService File: C:\\Temp\\malware.exe\nAccount: LocalSystem",
                4720: f"A user account was created.\nNew Account: backdoor_user\nCreated By: {user}",
                4740: f"A user account was locked out.\nLocked Account: {user}\nCaller: {computer}",
                4776: f"NTLM authentication attempt.\nAccount: {user}\nWorkstation: {computer}\nError: 0xC000006A",
                7036: f"The Windows Update service entered the running state.",
                1000: f"Faulting application: explorer.exe\nException code: 0xc0000005",
            }
            return templates.get(eid, f"Event {eid} occurred on {computer} by {user}.")

        event_pool = list(SECURITY_EVENT_TAGS.keys()) + [7036, 1000, 4634, 4689]
        events = []
        now = datetime.datetime.now()

        for i in range(min(max_records, 500)):
            if self._stop_event.is_set():
                break
            eid = random.choice(event_pool)
            user = random.choice(users)
            computer = random.choice(computers)
            ip = random.choice(ips)
            delta = datetime.timedelta(minutes=random.randint(0, 10080))  # last week
            ts = now - delta

            level_weights = {
                4625: "Audit Failure", 4776: "Audit Failure", 4771: "Audit Failure",
                4624: "Audit Success", 4672: "Audit Success",
                1000: "Error", 7034: "Error",
                7036: "Information", 4634: "Information",
            }
            level = level_weights.get(eid, random.choice(
                ["Information", "Information", "Information", "Warning", "Error", "Audit Success", "Audit Failure"]
            ))

            events.append({
                "TimeCreated": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "_datetime": ts,
                "EventID": eid,
                "Level": level,
                "Source": "Microsoft-Windows-Security-Auditing" if log_name == "Security" else "System",
                "Computer": computer,
                "User": user,
                "Message": fake_msg(eid, user, computer, ip),
                "LogName": log_name,
                "Tag": SECURITY_EVENT_TAGS.get(eid, ""),
            })

            if (i + 1) % 50 == 0:
                self.progress_cb(f"Generated {i+1} sample events…", int((i + 1) / max_records * 100))

        # Sort newest first
        events.sort(key=lambda e: e.get("TimeCreated", ""), reverse=True)
        self.progress_cb(f"Demo: {len(events):,} events ready.", 100)
        return events
