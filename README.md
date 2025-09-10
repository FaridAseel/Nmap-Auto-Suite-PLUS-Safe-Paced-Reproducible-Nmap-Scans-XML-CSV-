# Nmap Auto Suite PLUS
Safe, paced, metadata-rich Nmap automation with XML→CSV export.

## Features
- **Safe by design:** requires `--i-understand-lab-only`, disables DNS by default, adds human-like pacing.
- **Multi-phase scans:** host discovery, fast top-ports, full TCP, OS detection, HTTP enumeration; optional vuln, UDP top, and `-A`.
- **Reproducible & auditable:** deterministic seed, stored commands, timestamps, exit codes.
- **Rich exports:** per-phase outputs (`.nmap/.xml/.grep`), `INDEX.md`, `meta.jsonl`, plus unified XML→CSV aggregation.

## Quick Start
```bash
# Single target (CSV export)
python3 nmap_auto_suite_plus.py -t 192.168.1.10 --i-understand-lab-only --export-csv

# Batch targets with shuffle & human-like pacing
python3 nmap_auto_suite_plus.py -f hosts.txt --shuffle --sleep-min 0.6 --sleep-max 2.2 --i-understand-lab-only

# Add UDP + host discovery
python3 nmap_auto_suite_plus.py -t 10.0.0.5 --enable-udp --udp-top 200 --with-ping --i-understand-lab-only
