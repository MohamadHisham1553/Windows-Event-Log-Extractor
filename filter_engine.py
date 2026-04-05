"""
filter_engine.py - SOC Event Filtering Engine
Supports multi-dimensional filtering: IDs, keywords, time range, level, severity.
"""

import datetime
import json
import os
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field, asdict


@dataclass
class FilterPreset:
    name: str = "Default"
    event_ids: str = ""            # comma-separated
    keyword: str = ""
    start_time: str = ""           # "YYYY-MM-DD HH:MM:SS"
    end_time: str = ""
    errors_only: bool = False
    warnings_only: bool = False
    audit_success: bool = False
    audit_failure: bool = False
    quick_search: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> "FilterPreset":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class FilterEngine:
    """
    Filters a list of normalized event dicts against a FilterPreset.
    All comparisons are case-insensitive. Multiple Event IDs are OR-ed.
    Multiple level checkboxes are OR-ed. All active criteria are AND-ed.
    """

    # ── Public API ──────────────────────────────────────────────────────────

    def apply(self, events: List[Dict], preset: FilterPreset) -> List[Dict]:
        """Return subset of events matching all active criteria in preset."""
        ids     = self._parse_ids(preset.event_ids)
        kw      = preset.keyword.strip().lower()
        qs      = preset.quick_search.strip().lower()
        levels  = self._active_levels(preset)
        dt_from = self._parse_dt(preset.start_time)
        dt_to   = self._parse_dt(preset.end_time)

        results = []
        for ev in events:
            if ids and ev.get("EventID") not in ids:
                continue
            if levels and ev.get("Level", "") not in levels:
                continue
            if dt_from or dt_to:
                ev_dt = ev.get("_datetime")
                if ev_dt is None:
                    ev_dt = self._parse_dt(ev.get("TimeCreated", ""))
                if ev_dt:
                    if dt_from and ev_dt < dt_from:
                        continue
                    if dt_to and ev_dt > dt_to:
                        continue
            if kw and not self._keyword_match(ev, kw):
                continue
            if qs and not self._quick_match(ev, qs):
                continue
            results.append(ev)

        return results

    # ── Preset persistence ──────────────────────────────────────────────────

    PRESETS_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "filter_presets.json"
    )

    def save_preset(self, preset: FilterPreset):
        presets = self.load_all_presets()
        presets[preset.name] = preset.to_dict()
        with open(self.PRESETS_FILE, "w") as f:
            json.dump(presets, f, indent=2)

    def load_all_presets(self) -> Dict[str, Dict]:
        if not os.path.exists(self.PRESETS_FILE):
            return {}
        try:
            with open(self.PRESETS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def delete_preset(self, name: str):
        presets = self.load_all_presets()
        presets.pop(name, None)
        with open(self.PRESETS_FILE, "w") as f:
            json.dump(presets, f, indent=2)

    def get_preset(self, name: str) -> Optional[FilterPreset]:
        presets = self.load_all_presets()
        if name in presets:
            return FilterPreset.from_dict(presets[name])
        return None

    # ── Private helpers ─────────────────────────────────────────────────────

    def _parse_ids(self, ids_str: str) -> Set[int]:
        result = set()
        for token in ids_str.replace(";", ",").split(","):
            token = token.strip()
            if token:
                try:
                    result.add(int(token))
                except ValueError:
                    pass
        return result

    def _active_levels(self, preset: FilterPreset) -> Set[str]:
        levels: Set[str] = set()
        if preset.errors_only:
            levels.update({"Error", "Critical"})
        if preset.warnings_only:
            levels.add("Warning")
        if preset.audit_success:
            levels.add("Audit Success")
        if preset.audit_failure:
            levels.add("Audit Failure")
        return levels  # empty = no level filter

    def _parse_dt(self, s: str) -> Optional[datetime.datetime]:
        if not s or not s.strip():
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(s.strip(), fmt)
            except ValueError:
                pass
        return None

    def _keyword_match(self, ev: Dict, kw: str) -> bool:
        searchable = " ".join(str(v) for v in ev.values() if isinstance(v, str)).lower()
        return kw in searchable

    def _quick_match(self, ev: Dict, qs: str) -> bool:
        # Quick search checks common visible columns only
        cols = ["TimeCreated", "EventID", "Level", "Computer", "User", "Tag", "ShortMessage", "Source"]
        searchable = " ".join(str(ev.get(c, "")) for c in cols).lower()
        return qs in searchable


# ── Built-in investigation presets ──────────────────────────────────────────
BUILTIN_PRESETS = {
    "Logon Activity": FilterPreset(
        name="Logon Activity",
        event_ids="4624,4625,4634,4648,4672,4776",
    ),
    "Failed Logons": FilterPreset(
        name="Failed Logons",
        event_ids="4625,4771,4776",
        audit_failure=True,
    ),
    "Privilege Escalation": FilterPreset(
        name="Privilege Escalation",
        event_ids="4672,4673,4674",
    ),
    "Process Creation": FilterPreset(
        name="Process Creation",
        event_ids="4688",
    ),
    "Scheduled Tasks": FilterPreset(
        name="Scheduled Tasks",
        event_ids="4698,4699,4700,4701,4702",
    ),
    "Account Changes": FilterPreset(
        name="Account Changes",
        event_ids="4720,4722,4723,4724,4725,4726,4738,4740",
    ),
    "Log Tampering": FilterPreset(
        name="Log Tampering",
        event_ids="1102,1100,1104",
    ),
    "New Services": FilterPreset(
        name="New Services",
        event_ids="7045,4697",
    ),
    "All Errors": FilterPreset(
        name="All Errors",
        errors_only=True,
    ),
    "Audit Failures": FilterPreset(
        name="Audit Failures",
        audit_failure=True,
    ),
}
