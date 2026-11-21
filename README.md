
# Python Security Log Analyzer

A Python-based security tool that analyzes authentication logs, identifies failed login attempts, and flags IP addresses that reach a configurable alert threshold.

## Project Overview

This project demonstrates basic security log analysis using Python. It processes CSV authentication logs, validates records, counts successful and failed login attempts, and generates reports in TXT and JSON formats.

## Features

- Reads authentication logs from CSV files.
- Validates timestamps, IP addresses, and login statuses.
- Counts successful and failed login attempts.
- Groups failed attempts by source IP address.
- Flags IP addresses that meet or exceed a configurable threshold.
- Identifies invalid log records.
- Generates text and JSON reports.
- Supports custom input files and alert thresholds.

## Technologies Used

- Python 3
- CSV
- JSON
- IP Address Validation
- Command-line Argument Parsing

## Project Structure

```text
python-security-log-analyzer/
├── logs/
│   ├── sample-auth.log
│   └── test-auth.log
├── reports/
│   ├── security-report.txt
│   └── security-report.json
├── src/
│   └── analyzer.py
├── screenshots/
├── .gitignore
└── README.md
```

## How to Run

Run the analyzer using the default sample log:

```powershell
python src/analyzer.py
```

Set a custom detection threshold:

```powershell
python src/analyzer.py --threshold 7
```

Analyze a different log file:

```powershell
python src/analyzer.py --input logs/test-auth.log
```

## Detection Logic

The analyzer counts failed login attempts for each source IP address.

An alert is generated when an IP address reaches or exceeds the configured threshold.

For example, with a threshold of 5, an IP address with 6 failed attempts is flagged.

## Output

The program generates:

- `reports/security-report.txt` — readable security analysis report.
- `reports/security-report.json` — structured JSON results.

## Testing

The analyzer was tested using:

1. Normal authentication records.
2. A modified detection threshold.
3. Invalid IP addresses.
4. Unknown login statuses.

## Limitations

- Uses synthetic authentication log data.
- Detection is based on total failed attempts per IP, not a time window.
- An alert indicates suspicious activity for investigation; it does not prove malicious intent.
- Does not currently perform real-time monitoring.

## Disclaimer

This project is intended for educational purposes and cybersecurity portfolio demonstration.
