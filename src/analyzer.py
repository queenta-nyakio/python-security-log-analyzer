
import argparse
import csv
import ipaddress
import json
from collections import Counter
from pathlib import Path
from datetime import datetime


def analyze_logs(file_path, threshold):
    total_events = 0
    successful_logins = 0
    failed_logins = 0
    invalid_records = 0
    failed_by_ip = Counter()

    with open(file_path, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required_fields = {
            "timestamp", "source_ip", "username", "status"
        }

        if not reader.fieldnames or not required_fields.issubset(reader.fieldnames):
            raise ValueError("Log file is missing required CSV columns.")

        for row in reader:
            try:
                datetime.fromisoformat(
                    row["timestamp"].replace("Z", "+00:00")
                )

                ipaddress.ip_address(row["source_ip"])
                status = row["status"].strip().upper()

                if status not in {"SUCCESS", "FAILED"}:
                    raise ValueError("Unknown login status")

                total_events += 1

                if status == "SUCCESS":
                    successful_logins += 1
                else:
                    failed_logins += 1
                    failed_by_ip[row["source_ip"]] += 1

            except (ValueError, TypeError, AttributeError, KeyError):
                invalid_records += 1

    suspicious_ips = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= threshold
    }

    return {
        "total_events": total_events,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "invalid_records": invalid_records,
        "threshold": threshold,
        "suspicious_ips": suspicious_ips,
        "failed_attempts_by_ip": dict(failed_by_ip)
    }


def generate_report(results, output_file, json_file):
    lines = [
        "PYTHON SECURITY LOG ANALYSIS REPORT",
        "=" * 42,
        f"Total valid events: {results['total_events']}",
        f"Successful logins: {results['successful_logins']}",
        f"Failed logins: {results['failed_logins']}",
        f"Invalid records: {results['invalid_records']}",
        f"Detection threshold: {results['threshold']}",
        "",
        "FAILED LOGIN ATTEMPTS BY IP",
        "-" * 42
    ]

    for ip, count in sorted(
        results["failed_attempts_by_ip"].items(),
        key=lambda item: item[1],
        reverse=True
    ):
        if ip in results["suspicious_ips"]:
            lines.append(f"ALERT: {ip} - {count} failed attempts")
        else:
            lines.append(f"INFO:  {ip} - {count} failed attempts")

    if not results["suspicious_ips"]:
        lines.append("No IP addresses reached the alert threshold.")

    report_text = "\n".join(lines)

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(json_file).parent.mkdir(parents=True, exist_ok=True)

    Path(output_file).write_text(report_text, encoding="utf-8")
    Path(json_file).write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print("\n" + report_text)
    print(f"\nText report saved to: {output_file}")
    print(f"JSON report saved to: {json_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for suspicious activity."
    )

    parser.add_argument(
        "--input",
        default="logs/sample-auth.log",
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed login attempts needed to trigger an alert"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("Threshold must be at least 1.")

    input_file = Path(args.input)

    if not input_file.is_file():
        parser.error(f"Input file not found: {input_file}")

    try:
        results = analyze_logs(input_file, args.threshold)
        generate_report(
            results,
            "reports/security-report.txt",
            "reports/security-report.json"
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
