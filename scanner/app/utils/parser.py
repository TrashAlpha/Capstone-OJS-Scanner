"""
app/utils/parser.py
Utility functions untuk parsing dan transformasi data scan.
"""

import json
from app.config import logger


def parse_nuclei_jsonl(raw_output: str) -> list[dict]:
    """
    Parse raw Nuclei JSONL output menjadi list of dicts.

    Args:
        raw_output: String output dari Nuclei -jsonl

    Returns:
        List of parsed JSON objects
    """
    results = []

    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            logger.debug(f"Skipping non-JSON line: {line[:80]}")
            continue

    return results


def count_by_severity(findings: list[dict]) -> dict:
    """
    Hitung jumlah findings per severity level.

    Args:
        findings: List of normalized finding dicts

    Returns:
        dict {"critical": N, "high": N, "medium": N, "low": N, "info": N}
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in findings:
        severity = f.get("severity", "info").lower()
        if severity in counts:
            counts[severity] += 1
        else:
            counts["info"] += 1

    return counts


def normalize_finding(nuclei_finding: dict) -> dict:
    """
    Normalize satu finding dari format Nuclei ke format internal.

    Args:
        nuclei_finding: Raw finding dict dari Nuclei JSONL output

    Returns:
        Normalized finding dict
    """
    info = nuclei_finding.get("info", {})
    classification = info.get("classification", {})

    return {
        "template_id": nuclei_finding.get("template-id", nuclei_finding.get("templateID", "")),
        "template_name": info.get("name", ""),
        "severity": info.get("severity", "unknown"),
        "description": info.get("description", ""),
        "host": nuclei_finding.get("host", ""),
        "matched_at": nuclei_finding.get("matched-at", nuclei_finding.get("matched", "")),
        "matcher_name": nuclei_finding.get("matcher-name", ""),
        "extracted_results": nuclei_finding.get("extracted-results", []),
        "curl_command": nuclei_finding.get("curl-command", ""),
        "type": nuclei_finding.get("type", "http"),
        "cve_id": classification.get("cve-id", ""),
        "cwe_id": classification.get("cwe-id", ""),
        "cvss_score": classification.get("cvss-score", 0),
        "cvss_metrics": classification.get("cvss-metrics", ""),
        "tags": info.get("tags", []),
        "reference": info.get("reference", []),
        "timestamp": nuclei_finding.get("timestamp", ""),
    }


def findings_to_risk_engine_format(findings: list[dict]) -> list[dict]:
    """
    Konversi findings ke format yang diharapkan oleh Risk Engine /analyze endpoint.

    Risk Engine mengharapkan list of:
    {
        "name": str,
        "cvss_vector": str,
        "cwe_id": str,
        "extracted_results": str,
        "base_score": float
    }
    """
    risk_findings = []

    for f in findings:
        risk_findings.append({
            "name": f.get("template_name", f.get("template_id", "Unknown")),
            "cvss_vector": f.get("cvss_metrics", ""),
            "cwe_id": f.get("cwe_id", "N/A"),
            "extracted_results": (
                ", ".join(f.get("extracted_results", []))
                if isinstance(f.get("extracted_results"), list)
                else str(f.get("extracted_results", ""))
            ),
            "base_score": f.get("cvss_score", 0),
        })

    return risk_findings
