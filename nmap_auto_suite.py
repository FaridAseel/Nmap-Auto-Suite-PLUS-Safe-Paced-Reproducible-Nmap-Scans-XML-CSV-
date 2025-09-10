#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap Auto Suite — PLUS (safer defaults, pacing, rich metadata)
----------------------------------------------------------------
Ex:
  python3 nmap_auto_suite_plus.py -t 192.168.1.10 --i-understand-lab-only --export-csv
  python3 nmap_auto_suite_plus.py -f hosts.txt --shuffle --sleep-min 0.6 --sleep-max 2.2 --i-understand-lab-only
  python3 nmap_auto_suite_plus.py -t 10.0.0.5 --enable-udp --udp-top 200 --with-ping --i-understand-lab-only

"""

from __future__ import annotations
import argparse
import csv
import datetime as dt
import json
import os
import platform
import random
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Sequence, Tuple

# ----------------------------
# Utils
# ----------------------------

def now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def ts_slug() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def which_nmap() -> str:
    exe = "nmap.exe" if platform.system().lower().startswith("win") else "nmap"
    from shutil import which
    found = which(exe)
    if not found:
        sys.exit("[!] Nmap not found in PATH. Install from https://nmap.org/download.html and add to PATH.")
    return found


def sanitize_target(t: str) -> str:
    return re.sub(r"[/:]", "_", t)


def run_cmd(cmd: Sequence[str]) -> int:
    """Run a command; stream output to console. Return exit code."""
    try:
        proc = subprocess.run(cmd, check=False)
        return proc.returncode
    except KeyboardInterrupt:
        print("[!] Interrupted by user")
        raise

# ----------------------------
# XML → CSV export
# ----------------------------
CSV_FIELDS = [
    "run_id", "scan_file", "scan_name", "started", "target",
    "host", "hostname", "port", "protocol", "state", "reason",
    "service_name", "product", "version", "extrainfo", "cpe"
]


def parse_nmap_xml(xml_path: Path, run_id: str, scan_name_hint: str | None = None, target_hint: str | None = None) -> List[dict]:
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return []
    root = tree.getroot()
    started = root.attrib.get("startstr") or ""
    scan_name = scan_name_hint or xml_path.stem
    rows: List[dict] = []

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        ip = addr_el.attrib.get("addr") if addr_el is not None else ""

        hname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hname = hn.attrib.get("name", "")

        ports_el = host.find("ports")
        if ports_el is None:
            rows.append({
                "run_id": run_id, "scan_file": xml_path.name, "scan_name": scan_name, "started": started,
                "target": target_hint or "", "host": ip, "hostname": hname,
                "port": "", "protocol": "", "state": host.findtext("status[@state]", default=""),
                "reason": "", "service_name": "", "product": "", "version": "",
                "extrainfo": "", "cpe": "",
            })
            continue

        for p in ports_el.findall("port"):
            proto = p.attrib.get("protocol", "")
            portid = p.attrib.get("portid", "")
            state_el = p.find("state")
            state = state_el.attrib.get("state", "") if state_el is not None else ""
            reason = state_el.attrib.get("reason", "") if state_el is not None else ""
            svc_el = p.find("service")
            name = svc_el.attrib.get("name", "") if svc_el is not None else ""
            product = svc_el.attrib.get("product", "") if svc_el is not None else ""
            version = svc_el.attrib.get("version", "") if svc_el is not None else ""
            extrainfo = svc_el.attrib.get("extrainfo", "") if svc_el is not None else ""
            cpe = ""
            if svc_el is not None:
                cpe_el = svc_el.find("cpe")
                if cpe_el is not None and cpe_el.text:
                    cpe = cpe_el.text

            rows.append({
                "run_id": run_id,
                "scan_file": xml_path.name,
                "scan_name": scan_name,
                "started": started,
                "target": target_hint or "",
                "host": ip,
                "hostname": hname,
                "port": portid,
                "protocol": proto,
                "state": state,
                "reason": reason,
                "service_name": name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": cpe,
            })
    return rows


def export_all_xml_to_csv(outdir: Path, csv_path: Path, run_id: str) -> int:
    rows: List[dict] = []
    for xml_file in sorted(outdir.glob("*.xml")):
        # Expect filename like: ts_scanname_target.xml
        parts = xml_file.stem.split("_")
        scan_name = "_".join(parts[2:-1]) if len(parts) >= 4 else xml_file.stem
        tgt = parts[-1] if parts else ""
        rows.extend(parse_nmap_xml(xml_file, run_id, scan_name_hint=scan_name, target_hint=tgt))

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(rows)

    return len(rows)

# ----------------------------
# Scanning
# ----------------------------

def build_common(args: argparse.Namespace) -> List[str]:
    common = ["-T", str(args.timing)]
    if args.no_dns:
        common.append("-n")
    if args.with_ping:
        # host discovery separate stage; for normal scans we don't force -Pn
        pass
    else:
        # treat all online (safer if lab is isolated)
        common.append("-Pn")
    if args.min_rate and args.min_rate > 0:
        common += ["--min-rate", str(args.min_rate)]
    if args.max_rtt_timeout_ms:
        common += ["--max-rtt-timeout", f"{args.max_rtt_timeout_ms}ms"]
    return common


def run_nmap(nmap_bin: str, outdir: Path, run_id: str, scan_name: str,
             common: Sequence[str], extra: Sequence[str], targets: Sequence[str],
             sleep_min: float, sleep_max: float,
             meta_jl: Path) -> None:
    idx = outdir / "INDEX.md"
    with idx.open("a", encoding="utf-8") as fh_idx, meta_jl.open("a", encoding="utf-8") as fh_jl:
        for tgt in targets:
            ts = ts_slug()
            base = outdir / f"{ts}_{scan_name}_{sanitize_target(tgt)}"
            cmd = [nmap_bin] + list(common) + list(extra) + [
                tgt,
                "-oN", str(base) + ".nmap",
                "-oX", str(base) + ".xml",
                "-oG", str(base) + ".grep",
            ]
            cmd_str = " ".join(shlex.quote(c) for c in cmd)
            print(f"[+] {scan_name} -> {tgt}")

            # INDEX.md
            fh_idx.write(
                f"\n## {scan_name} — {tgt}\n\n"
                f"````bash\n{cmd_str}\n````\n"
            )

            start = now_iso()
            rc = run_cmd(cmd)
            end = now_iso()

            meta = {
                "run_id": run_id,
                "scan_name": scan_name,
                "target": tgt,
                "cmd": cmd,
                "start": start,
                "end": end,
                "exit_code": rc,
            }
            fh_jl.write(json.dumps(meta, ensure_ascii=False) + "\n")

            # human-like pause between targets
            time.sleep(random.uniform(sleep_min, sleep_max))

# ----------------------------
# Main
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description="Nmap Auto Suite — PLUS (safer, paced, metadata)")

    # Targets
    g_req = ap.add_argument_group("Targets")
    g_req.add_argument("-t", "--target", help="Single target (IP/host/CIDR)")
    g_req.add_argument("-f", "--targets-file", help="File with targets (one per line)")

    # Safety gate
    ap.add_argument("--i-understand-lab-only", action="store_true", help="Required safety confirmation (lab use only)")

    # Output
    ap.add_argument("-o", "--outdir", default=f"nmap_plus_{ts_slug()}", help="Output directory")
    ap.add_argument("--run-id", default=f"run{ts_slug()}", help="Custom run identifier")
    ap.add_argument("--seed", type=int, help="Random seed (reproducibility)")

    # Intensity / pacing
    ap.add_argument("-T", "--timing", type=int, default=3, choices=[0,1,2,3,4,5], help="Timing template 0-5 (default 3)")
    ap.add_argument("--min-rate", type=int, default=100, help="Minimum packet rate (pps), default 100")
    ap.add_argument("--max-rtt-timeout-ms", type=int, default=0, help="Cap on probe RTT (ms), 0=off")
    ap.add_argument("--sleep-min", type=float, default=0.4, help="Min sleep between targets (s)")
    ap.add_argument("--sleep-max", type=float, default=1.2, help="Max sleep between targets (s)")
    ap.add_argument("--scan-sleep-min", type=float, default=1.0, help="Min sleep between scan phases (s)")
    ap.add_argument("--scan-sleep-max", type=float, default=3.0, help="Max sleep between scan phases (s)")
    ap.add_argument("--shuffle", action="store_true", help="Randomize order of scan phases")

    # Discovery / DNS
    ap.add_argument("--with-ping", action="store_true", help="Perform host discovery (-sn) stage")
    ap.add_argument("--no-dns", action="store_true", default=True, help="Disable DNS resolution (-n)")
    ap.add_argument("--with-dns", dest="no_dns", action="store_false", help="Enable DNS resolution")

    # Ports
    ap.add_argument("-p", "--ports", default="-p-", help="Port options: all/-p-/range/list")
    ap.add_argument("--top-ports", type=int, default=1000, help="Top N ports for fast TCP scan")

    # Scan toggles
    ap.add_argument("--enable-fast", action="store_true", default=True, help="Enable fast TCP top ports")
    ap.add_argument("--enable-full", action="store_true", default=True, help="Enable full TCP scan")
    ap.add_argument("--enable-os", action="store_true", default=True, help="Enable OS detection")
    ap.add_argument("--enable-http", action="store_true", default=True, help="Enable HTTP enumeration")
    ap.add_argument("--enable-vuln", action="store_true", default=False, help="Enable generic vuln scripts")
    ap.add_argument("--enable-udp", action="store_true", default=False, help="Enable UDP top ports scan")
    ap.add_argument("--enable-aggressive", action="store_true", default=False, help="Enable -A aggressive scan")

    # HTTP script ports
    ap.add_argument("--http-ports", default="80,443,8080", help="Ports for HTTP scripts")

    # Export
    ap.add_argument("--export-csv", action="store_true", default=True, help="Export aggregated CSV")
    ap.add_argument("--no-export-csv", dest="export_csv", action="store_false", help="Do not export CSV")

    args = ap.parse_args()

    # Safety confirmation
    if not args.i_understand_lab_only:
        sys.exit("[!] Refusing to run without --i-understand-lab-only. Lab/authorized use only.")

    # Seed
    if args.seed is not None:
        random.seed(args.seed)

    # Targets
    if not args.target and not args.targets_file:
        sys.exit("[!] -t/--target or -f/--targets-file is required")

    if args.targets_file:
        targets = [ln.strip() for ln in Path(args.targets_file).read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith('#')]
    else:
        targets = [args.target]

    nmap_bin = which_nmap()
    outdir = Path(args.outdir)
    ensure_dir(outdir)

    # Files
    (outdir / "INDEX.md").write_text(
        f"# Nmap Auto Suite — PLUS\nRun: {args.run_id}\nDate: {now_iso()}\n", encoding="utf-8"
    )
    meta_jl = outdir / "meta.jsonl"
    meta_jl.write_text("")

    # Build common args
    common = build_common(args)

    # Define phases
    phases: List[Tuple[str, List[str]]] = []
    if args.with_ping:
        phases.append(("01_host_discovery", ["-sn"]))
    if args.enable_fast:
        phases.append((f"02_fast_tcp_top{args.top_ports}", ["-sS", "-sV", "--top-ports", str(args.top_ports)]))
    if args.enable_full:
        # ports selector
        port_args = ["-p-"] if args.ports in ("-p-", "all") else (["-p", args.ports] if args.ports else ["-p-"])
        phases.append(("03_full_tcp", ["-sS", "-sV", *port_args]))
    if args.enable_os:
        phases.append(("04_os_detection", ["-O", "--osscan-guess"]))
    if args.enable_http:
        http_scripts = ",".join([
            "http-enum", "http-methods", "http-headers", "http-title",
            "http-security-headers", "http-server-header", "http-robots.txt",
        ])
        phases.append(("05_http_enum", ["-p", args.http_ports, "--script", http_scripts]))
    if args.enable_vuln:
        phases.append(("06_vuln", ["--script", "vuln"]))
    if args.enable_udp:
        phases.append(("07_udp_top", ["-sU", "--top-ports", "200", "-sV"]))
    if args.enable_aggressive:
        phases.append(("08_aggressive", ["-A"]))

    if not phases:
        sys.exit("[!] No scan phases enabled.")

    if args.shuffle:
        # Keep host discovery first if present
        head = [ph for ph in phases if ph[0].startswith("01_")]
        tail = [ph for ph in phases if not ph[0].startswith("01_")]
        random.shuffle(tail)
        phases = head + tail

    # Write plan to INDEX
    with (outdir / "INDEX.md").open("a", encoding="utf-8") as fh:
        fh.write("\n## Plan\n\n")
        for name, extra in phases:
            fh.write(f"- {name}: {' '.join(extra)}\n")

    # Execute phases
    for name, extra in phases:
        run_nmap(
            nmap_bin=nmap_bin,
            outdir=outdir,
            run_id=args.run_id,
            scan_name=name,
            common=common,
            extra=extra,
            targets=targets,
            sleep_min=args.sleep_min,
            sleep_max=args.sleep_max,
            meta_jl=meta_jl,
        )
        # Human-like gap between phases
        time.sleep(random.uniform(args.scan_sleep_min, args.scan_sleep_max))

    # Export CSV
    if args.export_csv:
        csv_path = outdir / "nmap_aggregated.csv"
        count = export_all_xml_to_csv(outdir, csv_path, run_id=args.run_id)
        print(f"[+] CSV exported: {csv_path} (rows: {count})")

    print(f"[Done] Results in: {outdir}")


if __name__ == "__main__":
    main()
