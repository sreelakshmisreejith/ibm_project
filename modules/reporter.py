import csv
import os
from datetime import datetime

def generate_evidence_report(report_path, evidence_data):

    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    fieldnames = [
        "Case ID",
        "Investigator",
        "System Name",
        "File Name",
        "File Path",
        "File Type",
        "File Size (KB)",
        "Permissions",
        "Anomaly Flag",
        "Created Time",
        "Modified Time",
        "Accessed Time",
        "SHA256 Hash",
        "MD5 Hash",
        "Status",
        "Risk Level",
        "Category",
        "Evidence Collected On"
    ]

    with open(report_path, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(evidence_data)