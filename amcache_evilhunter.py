#!/usr/bin/env python3

"""
AmCache-EvilHunter : Fast AMCache Triage Hash 'em All (Without Wasting API Credits)
Author: Thomas Lowagie
Based on the works of Cristian Souza (cristianmsbr@gmail.com)
Short script for Pass the SALT rump session
"""

import argparse
import json
import sys
import csv
import re
import os
from pathlib import Path
from functools import lru_cache
from datetime import datetime, timedelta

import requests
from requests.exceptions import HTTPError

from Registry.Registry import Registry as RegistryHive
from Registry.RegistryParse import ParseException as RegistryParseException
#pip install python-registry requests

from rich.console import Console
from rich.table import Table
from rich.live import Live

VERSION = "0.0.1"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{hash}"

# Core fields to persist for SHA-1–bearing records
KEEP_FIELDS = {
    # Common uninstall/AppV entries
    "ProgramId", "ProgramInstanceId", "Name", "Version", "Publisher",
    "Language", "InstallDate", "Source", "RootDirPath", "HiddenArp",
    "UninstallString", "RegistryKeyPath", "MsiPackageCode",
    "MsiProductCode", "MsiInstallDate", "(default)", "FilePath",
    # Amcache-specific entries
    "SHA-1", "LowerCaseLongPath", "OriginalFileName", "BinFileVersion",
    "BinaryType", "ProductName", "ProductVersion", "LinkDate",
    "BinProductVersion", "Size", "Usn",
    # Computed date
    "RecordDate",
}

console = Console()

HASHLOOKUP_URL = "https://hashlookup.circl.lu/bulk/sha1"

def query_hashlookup_bulk(sha1_hashes):
    """Query CIRCL Hashlookup bulk endpoint and return set of known SHA-1."""
    try:
        resp = requests.post(
            HASHLOOKUP_URL,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"hashes": sha1_hashes}),
            timeout=15
        )
        if resp.status_code == 200:
            results = resp.json()
            return set(entry["SHA-1"] for entry in results)
        elif resp.status_code == 404:
            return set()
        else:
            console.print(f"[red]Hashlookup error {resp.status_code}: {resp.text}[/]")
            return set()
    except Exception as e:
        console.print(f"[red]Hashlookup request failed: {e}[/]")
        return set()


def find_suspicious(data):
    """
    Keep only records whose FilePath basename exactly matches one of our
    known suspicious executables (case‐insensitive), ends with .exe,
    OR is a one‐letter/one‐digit name, OR looks like a random hex string.
    """
    suspicious_patterns = {
        # Malware families
        "lb3", "lockbit", "ryuk", "darkside", "conti",
        "maze", "emotet", "trickbot", "qbot", "cerber",
        # Masquerade targets
        "svchost", "scvhost", "svch0st", "svhost",
        "rundll32", "rundll",
        "explorer", "expl0rer", "expiorer",
        "csrss", "csrs",
        "winlogon", "winlog0n", "winlogin",
        "lsass", "lsas", "isass",
        "services", "service", "svces",
        "dllhost", "dihost", "dllhst",
        "conhost", "conhost1", "conhost64",
        "spoolsv", "splsv", "spools",
        "taskhostw", "taskhost", "taskhost64", "taskhostw1",
        "wmiprvse",
        "mshta", "mshta32", "wscript", "wscript1", "cscript", "cscript5",
        "regsvr32", "regsvr321",
    }
    hex_re = re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE)

    filtered = {}
    for cat, recs in data.items():
        keep = {}
        for rec, vals in recs.items():
            fp = vals.get("Name", "")
            name = Path(fp).name.lower()
            if not name.endswith(".exe"):
                continue
            stem = name[:-4]
            if (
                stem in suspicious_patterns
                or len(stem) == 1
                or stem.isdigit()
                or hex_re.match(stem)
            ):
                keep[rec] = vals
        if keep:
            filtered[cat] = keep
    return filtered


class AmcacheParser:
    """Parser for offline Amcache.hve registry hive."""
    def __init__(self, hive_path, start=None, end=None):
        # Verify file exists
        if not hive_path.exists():
            raise FileNotFoundError(f"Hive file not found: {hive_path}")
        # Attempt to load the registry hive, catch invalid-file errors
        try:
            self.registry = RegistryHive(str(hive_path))
        except RegistryParseException:
            print(
                f"Error: '{hive_path}' is not a valid registry hive "
                "(invalid REGF signature).",
                file=sys.stderr
            )
            sys.exit(1)

        self.start = start
        self.end = end

    def compute_record_date(self, vals, rec_key):
        """Convert Windows FILETIME values to datetime, fallback to key timestamp."""
        def filetime_to_dt(ft_raw):
            try:
                if isinstance(ft_raw, bytes):
                    ft_int = int.from_bytes(ft_raw, "little", signed=False)
                elif isinstance(ft_raw, int):
                    ft_int = ft_raw
                else:
                    return None
                return datetime(1601, 1, 1) + timedelta(microseconds=ft_int // 10)
            except (TypeError, ValueError):
                return None

        for fname in ("LastModifiedTime", "LastWriteTime", "ModifiedTime", "CreationTime"):
            dt = filetime_to_dt(vals.get(fname))
            if dt:
                return dt
        return rec_key.timestamp()

    def parse(self):
        """Walk the Amcache hive and collect record values."""
        root = self.registry.open("Root")
        subs = {k.name(): k for k in root.subkeys()}
        parent = subs.get("InventoryApplicationFile") or subs.get("File") or root

        data = {"Amcache": {}}
        for rec in parent.subkeys():
            vals = {v.name(): v.value() for v in rec.values()}
            vals["FilePath"] = vals.get("LowerCaseLongPath", rec.name())

            record_dt = self.compute_record_date(vals, rec)
            vals["RecordDate"] = record_dt.isoformat()

            if "FileId" in vals:
                vals["SHA-1"] = vals.pop("FileId")

            rd = record_dt.date()
            if self.start and rd < self.start.date():
                continue
            if self.end and rd > self.end.date():
                continue

            data["Amcache"][rec.name()] = vals

        return data


def normalize_data(data):
    """Trim whitespace on all strings; strip leading zeros on SHA-1."""
    for recs in data.values():
        for vals in recs.values():
            for k, v in list(vals.items()):
                if isinstance(v, str):
                    nv = v.strip()
                    if k in ("SHA-1", "SHA1") and nv.startswith("0000"):
                        nv = nv[4:]
                    vals[k] = nv


def prune_record(vals, vt_enabled):
    """Select only the KEEP_FIELDS (plus VT fields) from vals."""
    if not vals.get("SHA-1"):
        return {}
    out = {}
    fields = set(KEEP_FIELDS)
    if vt_enabled:
        fields.update({"VT_Detections", "VT_TotalEngines", "VT_Ratio"})
    for field in fields:
        if field in vals:
            out[field] = vals[field]
    return out


@lru_cache(maxsize=None)
def lookup_vt(hash_value, api_key):
    """Fetch VT stats for a hash; return (detections, total, ratio)."""
    try:
        resp = requests.get(
            VT_API_URL.format(hash=hash_value),
            headers={"x-apikey": api_key},
            timeout=15
        )
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        det = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in stats)
        return det, total, f"{det}/{total}"
    except HTTPError as e:
        if e.response and e.response.status_code == 404:
            return None, None, "N/A"
        return None, None, ""
    except (ValueError, KeyError):
        return None, None, ""


def print_table(data, vt_enabled, api_key=None, only_detections=False):
    """Live-render a table of records; optionally filter VT detections."""
    any_printed = False
    rows_to_print = []

    def make_table():
        tbl = Table(show_header=True, header_style="bold cyan", expand=True)
        tbl.add_column("SHA-1", style="dim")
        tbl.add_column("Name")
        tbl.add_column("RecordDate", justify="center")
        if vt_enabled:
            tbl.add_column("VT", justify="right")
        return tbl

    table = make_table()
    with Live(table, console=console, refresh_per_second=4) as live:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                name = vals.get("Name", "")
                record_date_str = vals.get("RecordDate", "")
                try:
                    record_dt = datetime.fromisoformat(record_date_str)
                except ValueError:
                    record_dt = record_date_str

                vt_cell = ""
                style = None
                if vt_enabled and api_key:
                    det, _, vt_cell = lookup_vt(sha, api_key)
                    if det and det > 0:
                        style = "bold red"
                    if only_detections and (det is None or det == 0):
                        continue

                row = [sha, name, record_date_str]
                if vt_enabled:
                    row.append(vt_cell)

                rows_to_print.append((record_dt, row, style))
                rows_to_print.sort(key=lambda t: t[0])

                table = make_table()
                for _, r, st in rows_to_print:
                    table.add_row(*r, style=st)
                live.update(table)

                any_printed = True

    if not any_printed:
        msg = "No entries found."
        if vt_enabled and only_detections:
            msg = "No entries with VT detections found."
        console.print(f"[bold red]{msg}[/]")
        sys.exit(1 if vt_enabled and only_detections else 0)


def write_json(path, data, vt_enabled, api_key):
    """Write filtered records to JSON file."""
    if vt_enabled and api_key:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                det, total, ratio = lookup_vt(sha, api_key)
                vals["VT_Detections"] = det
                vals["VT_TotalEngines"] = total
                vals["VT_Ratio"] = ratio

    out_list = []
    for cat, recs in data.items():
        for rec, vals in recs.items():
            kept = prune_record(vals, vt_enabled)
            if not kept:
                continue
            kept["Category"] = cat
            kept["RecordName"] = rec
            out_list.append(kept)

    out_list.sort(key=lambda v: v.get("RecordDate", ""))
    with path.open("w", encoding="utf-8") as f:
        json.dump(out_list, f, indent=4)


def write_csv(path, data, vt_enabled, api_key):
    """Write filtered records to CSV file."""
    if vt_enabled and api_key:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                det, total, ratio = lookup_vt(sha, api_key)
                vals["VT_Detections"] = det
                vals["VT_TotalEngines"] = total
                vals["VT_Ratio"] = ratio

    rows = []
    for cat, recs in data.items():
        for rec, vals in recs.items():
            kept = prune_record(vals, vt_enabled)
            if not kept:
                continue
            row = {"Category": cat, "RecordName": rec}
            row.update(kept)
            rows.append(row)

    headers = ["Category", "RecordName", "SHA-1"]
    other = [f for f in KEEP_FIELDS if f not in {"SHA-1", "FilePath"}]
    headers += sorted(other) + ["FilePath"]
    if vt_enabled:
        headers += ["VT_Detections", "VT_TotalEngines", "VT_Ratio"]

    rows.sort(key=lambda r: r.get("RecordDate", ""))
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


def main():
    """CLI entry point for amcache_evilhunter."""
    parser = argparse.ArgumentParser(
        description="AmCache-EvilHunter: parse and analyze a Windows Amcache.hve registry hive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"AmCache-EvilHunter {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )
    parser.add_argument(
        '--version', '-V',
        action='version',
        version=f"AmCache-EvilHunter {VERSION} by Cristian Souza (cristianmsbr@gmail.com)"
    )
    parser.add_argument(
        "-i", "--input",
        type=Path,
        required=True,
        help="Path to Amcache.hve"
    )
    parser.add_argument(
        "--start",
        type=str,
        help="YYYY-MM-DD; only records on or after this date"
    )
    parser.add_argument(
        "--end",
        type=str,
        help="YYYY-MM-DD; only records on or before this date"
    )
    parser.add_argument(
        "--search",
        type=str,
        help="Comma-separated terms (case-insensitive)"
    )
    parser.add_argument(
        "--find-suspicious",
        action="store_true",
        help="Filter only records matching known suspicious patterns"
    )
    parser.add_argument(
        "-v", "--vt",
        action="store_true",
        help="Enable VirusTotal lookups (requires VT_API_KEY environment variable)"
    )
    parser.add_argument(
        "--only-detections",
        action="store_true",
        help="Show/save only files with ≥1 VT detection"
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Path to write full JSON"
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="Path to write full CSV"
    )
    args = parser.parse_args()

    api_key = None
    if args.vt:
        api_key = os.getenv("VT_API_KEY")
        if not api_key:
            print("Error: VT_API_KEY environment variable not set", file=sys.stderr)
            sys.exit(1)

    start_dt = None
    end_dt = None
    if args.start:
        try:
            start_dt = datetime.strptime(args.start, "%Y-%m-%d")
        except ValueError:
            print("Error: --start must be YYYY-MM-DD", file=sys.stderr)
            sys.exit(1)
    if args.end:
        try:
            end_dt = datetime.strptime(args.end, "%Y-%m-%d")
        except ValueError:
            print("Error: --end must be YYYY-MM-DD", file=sys.stderr)
            sys.exit(1)
    if start_dt and end_dt and start_dt > end_dt:
        print("Error: --start must be on or before --end", file=sys.stderr)
        sys.exit(1)

    search_terms = None
    if args.search:
        search_terms = [t.strip().lower() for t in args.search.split(",") if t.strip()]

    try:
        parser = AmcacheParser(args.input, start_dt, end_dt)
        data = parser.parse()

        normalize_data(data)
        # ---- Hashlookup filtering ----
        all_sha1 = {
            vals["SHA-1"]
            for recs in data.values()
            for vals in recs.values()
            if "SHA-1" in vals
        }

        known_sha1 = {h.lower() for h in query_hashlookup_bulk(list(all_sha1))}
        #print(known_sha1)
        if known_sha1:
            console.print(f"[green]Hashlookup: {len(known_sha1)} known hashes found[/]")

        # Filtrer les fichiers connus
        for cat in list(data.keys()):
            recs = data[cat]
            for rec in list(recs.keys()):
                if recs[rec].get("SHA-1") in known_sha1:
                    del recs[rec]
            if not recs:
                del data[cat]

        if search_terms:
            filtered = {}
            for cat, recs in data.items():
                keep = {}
                for rec, vals in recs.items():
                    if any(term in vals.get("FilePath", "").lower() for term in search_terms):
                        keep[rec] = vals
                if keep:
                    filtered[cat] = keep
            data = filtered

        if args.find_suspicious:
            data = find_suspicious(data)

        print_table(
            data,
            vt_enabled=args.vt,
            api_key=api_key,
            only_detections=args.only_detections,
        )

        if args.json:
            write_json(
                args.json,
                data,
                vt_enabled=args.vt,
                api_key=api_key,
            )
        if args.csv:
            write_csv(
                args.csv,
                data,
                vt_enabled=args.vt,
                api_key=api_key,
            )

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except HTTPError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/]")
        sys.exit(0)
