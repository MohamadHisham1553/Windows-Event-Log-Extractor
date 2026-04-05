"""
parser.py - Event Field Extraction and Normalization
Parses raw event dicts into normalized, display-ready records.
"""

import re
from typing import Dict, List, Optional
from log_reader import CRITICAL_IDS, HIGH_IDS, MEDIUM_IDS, SECURITY_EVENT_TAGS


# ── Colour tier constants (used by GUI) ────────────────────────────────────
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

# Level-string → severity mapping
LEVEL_SEVERITY = {
    "Audit Failure": SEVERITY_HIGH,
    "Error":         SEVERITY_MEDIUM,
    "Critical":      SEVERITY_CRITICAL,
    "Warning":       SEVERITY_MEDIUM,
    "Audit Success": SEVERITY_INFO,
    "Information":   SEVERITY_INFO,
    "Unknown":       SEVERITY_INFO,
}


class EventParser:
    """
    Converts raw event dicts (from EventLogReader) into normalized records
    suitable for display, filtering, and export.
    """

    # Regex patterns for extracting key fields from Message text
    _PATTERNS = {
        "CommandLine": re.compile(r"(?:Command Line|CommandLine)[:\s]+(.+)", re.IGNORECASE),
        "Image":       re.compile(r"(?:New Process Name|Process Name|Image)[:\s]+(.+)", re.IGNORECASE),
        "TargetUser":  re.compile(r"(?:Account Name|Target Account Name|New Account Name)[:\s]+(.+)", re.IGNORECASE),
        "LogonType":   re.compile(r"Logon Type[:\s]+(\d+)", re.IGNORECASE),
        "SourceIP":    re.compile(r"(?:Source Network Address|Source IP|Workstation Name)[:\s]+(.+)", re.IGNORECASE),
        "ServiceName": re.compile(r"Service Name[:\s]+(.+)", re.IGNORECASE),
        "TaskName":    re.compile(r"Task Name[:\s]+(.+)", re.IGNORECASE),
    }

    # Logon type map
    LOGON_TYPES = {
        "2": "Interactive", "3": "Network", "4": "Batch",
        "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
        "9": "NewCredentials", "10": "RemoteInteractive",
        "11": "CachedInteractive", "12": "CachedRemoteInteractive",
        "13": "CachedUnlock",
    }

    def normalize(self, raw: Dict) -> Dict:
        """Return a fully-normalized event record."""
        event_id = int(raw.get("EventID", 0))
        level    = raw.get("Level", "Unknown")
        message  = raw.get("Message", "")
        tag      = raw.get("Tag") or SECURITY_EVENT_TAGS.get(event_id, "")

        severity = self._compute_severity(event_id, level)
        extracted = self._extract_fields(message)

        # Truncate message for table display
        short_msg = message.replace("\r", "").replace("\n", " | ")
        short_msg = short_msg[:300] + "…" if len(short_msg) > 300 else short_msg

        return {
            # Core fields
            "TimeCreated":  raw.get("TimeCreated", ""),
            "_datetime":    raw.get("_datetime"),
            "EventID":      event_id,
            "Level":        level,
            "Source":       raw.get("Source", ""),
            "Computer":     raw.get("Computer", ""),
            "User":         raw.get("User", ""),
            "LogName":      raw.get("LogName", ""),
            # Enriched
            "Tag":          tag,
            "Severity":     severity,
            "ShortMessage": short_msg,
            "FullMessage":  message,
            # Extracted sub-fields
            "CommandLine":  extracted.get("CommandLine", ""),
            "Image":        extracted.get("Image", ""),
            "TargetUser":   extracted.get("TargetUser", ""),
            "LogonType":    self.LOGON_TYPES.get(extracted.get("LogonType", ""), extracted.get("LogonType", "")),
            "SourceIP":     extracted.get("SourceIP", ""),
            "ServiceName":  extracted.get("ServiceName", ""),
            "TaskName":     extracted.get("TaskName", ""),
        }

    def normalize_batch(
        self,
        raw_list: List[Dict],
        progress_cb=None,
    ) -> List[Dict]:
        """Normalize a list of raw events, with optional progress callback."""
        results = []
        total = len(raw_list)
        for i, raw in enumerate(raw_list):
            results.append(self.normalize(raw))
            if progress_cb and (i + 1) % 500 == 0:
                progress_cb(f"Parsing {i+1}/{total}…", int((i + 1) / total * 100))
        return results

    # ── Private helpers ─────────────────────────────────────────────────────

    def _compute_severity(self, event_id: int, level: str) -> str:
        if event_id in CRITICAL_IDS:
            return SEVERITY_CRITICAL
        if level == "Critical":
            return SEVERITY_CRITICAL
        if event_id in HIGH_IDS or level == "Audit Failure":
            return SEVERITY_HIGH
        if event_id in MEDIUM_IDS or level in ("Error", "Warning"):
            return SEVERITY_MEDIUM
        return SEVERITY_INFO

    def _extract_fields(self, message: str) -> Dict[str, str]:
        results = {}
        for field, pattern in self._PATTERNS.items():
            match = pattern.search(message)
            if match:
                results[field] = match.group(1).strip()
        return results
