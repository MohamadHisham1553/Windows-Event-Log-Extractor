"""
exporter.py - Export filtered events to CSV / JSON / TXT
"""

import csv
import json
import os
import datetime
from typing import List, Dict


# Columns written to CSV (order matters)
CSV_COLUMNS = [
    "TimeCreated", "EventID", "Level", "Severity", "Tag",
    "Computer", "User", "Source", "LogName",
    "CommandLine", "Image", "TargetUser", "LogonType", "SourceIP",
    "ServiceName", "TaskName", "ShortMessage",
]


class Exporter:

    def export_csv(self, events: List[Dict], path: str) -> int:
        """Write events to CSV. Returns number of rows written."""
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for ev in events:
                writer.writerow({col: ev.get(col, "") for col in CSV_COLUMNS})
        return len(events)

    def export_json(self, events: List[Dict], path: str) -> int:
        """Write events to pretty-printed JSON. Returns number written."""
        exportable = []
        for ev in events:
            row = {k: v for k, v in ev.items() if not k.startswith("_")}
            exportable.append(row)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(exportable, f, indent=2, default=str)
        return len(events)

    def export_txt(self, events: List[Dict], path: str) -> int:
        """Write a human-readable report. Returns number written."""
        with open(path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("  WINDOWS EVENT LOG EXTRACTOR — SOC REPORT\n")
            f.write(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Events:    {len(events)}\n")
            f.write("=" * 80 + "\n\n")

            for i, ev in enumerate(events, 1):
                f.write(f"[{i}] ── Event ─────────────────────────────────────────────\n")
                f.write(f"  Time:      {ev.get('TimeCreated','')}\n")
                f.write(f"  Event ID:  {ev.get('EventID','')}  [{ev.get('Tag','')}]\n")
                f.write(f"  Level:     {ev.get('Level','')}  ({ev.get('Severity','')})\n")
                f.write(f"  Computer:  {ev.get('Computer','')}\n")
                f.write(f"  User:      {ev.get('User','')}\n")
                f.write(f"  Source:    {ev.get('Source','')}\n")
                if ev.get("CommandLine"):
                    f.write(f"  CmdLine:   {ev['CommandLine']}\n")
                if ev.get("Image"):
                    f.write(f"  Process:   {ev['Image']}\n")
                if ev.get("SourceIP"):
                    f.write(f"  Src IP:    {ev['SourceIP']}\n")
                f.write(f"  Message:\n")
                for line in ev.get("FullMessage", "").split("\n"):
                    f.write(f"    {line}\n")
                f.write("\n")
        return len(events)

    def auto_export(self, events: List[Dict], path: str) -> int:
        """Choose format based on file extension."""
        ext = os.path.splitext(path)[1].lower()
        if ext == ".csv":
            return self.export_csv(events, path)
        elif ext == ".json":
            return self.export_json(events, path)
        else:
            return self.export_txt(events, path)
