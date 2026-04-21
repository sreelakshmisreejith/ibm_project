import os
from datetime import datetime

from modules.hasher import generate_both_hashes
from modules.metadata import extract_metadata
from modules.reporter import generate_evidence_report
from modules.scanner import scan_directory


def scan_forensic_directory(
    directory_path,
    *,
    case_id,
    investigator,
    system_name,
    breach_date,
    report_path=None,
):
    """
    Scan a directory and build forensic evidence records.

    Returns a dictionary with summary data and collected records.
    """
    if not os.path.exists(directory_path):
        raise FileNotFoundError("Directory does not exist")

    file_list = scan_directory(directory_path)
    forensic_records = []

    for file_path in file_list:
        metadata = extract_metadata(file_path)

        hashes = generate_both_hashes(file_path)
        metadata["SHA256 Hash"] = hashes["SHA256 Hash"]
        metadata["MD5 Hash"] = hashes["MD5 Hash"]

        if metadata["Modified Time"] > breach_date:
            metadata["Status"] = "Modified After Breach"
            metadata["Risk Level"] = "High"
        else:
            metadata["Status"] = "Normal"
            metadata["Risk Level"] = "Low"

        lower_path = file_path.lower()
        lower_name = metadata["File Name"].lower()

        if "ehr" in lower_path or "electronic" in lower_path or "patient" in lower_name:
            metadata["Category"] = "Electronic Health Record"
        elif "billing" in lower_path or "invoice" in lower_name or "payment" in lower_name:
            metadata["Category"] = "Billing & Financial"
        elif "lab" in lower_path or "test" in lower_name or "result" in lower_name:
            metadata["Category"] = "Laboratory Report"
        elif "radiology" in lower_path or "xray" in lower_name or "scan" in lower_name:
            metadata["Category"] = "Radiology & Imaging"
        elif "prescription" in lower_path or "pharmacy" in lower_name or "drug" in lower_name:
            metadata["Category"] = "Pharmacy & Prescription"
        elif "report" in lower_name or "summary" in lower_name or "cardiac" in lower_name:
            metadata["Category"] = "Medical Report"
        elif metadata["File Type"] in [".xlsx", ".csv"]:
            metadata["Category"] = "Structured Healthcare Dataset"
        else:
            metadata["Category"] = "General / Unclassified"

        metadata["Case ID"] = case_id
        metadata["Investigator"] = investigator
        metadata["System Name"] = system_name
        metadata["Evidence Collected On"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        metadata["Created Time"] = metadata["Created Time"].strftime("%Y-%m-%d %H:%M:%S")
        metadata["Modified Time"] = metadata["Modified Time"].strftime("%Y-%m-%d %H:%M:%S")
        metadata["Accessed Time"] = metadata["Accessed Time"].strftime("%Y-%m-%d %H:%M:%S")

        forensic_records.append(metadata)

    if report_path and forensic_records:
        generate_evidence_report(report_path, forensic_records)

    total_files = len(forensic_records)
    high_risk = sum(1 for record in forensic_records if record["Risk Level"] == "High")
    low_risk = sum(1 for record in forensic_records if record["Risk Level"] == "Low")

    return {
        "case_id": case_id,
        "investigator": investigator,
        "system_name": system_name,
        "breach_date": breach_date.strftime("%Y-%m-%d"),
        "total_files": total_files,
        "high_risk": high_risk,
        "low_risk": low_risk,
        "records": forensic_records,
        "report_path": report_path,
        "report_url": "/reports/evidence_report.csv" if report_path else None,
    }
