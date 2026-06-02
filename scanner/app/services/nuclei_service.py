"""
app/services/nuclei_service.py
Wrapper untuk menjalankan Nuclei CLI sebagai external vulnerability scanner.
Menjalankan Nuclei binary via subprocess dengan custom OJS templates.
"""

import subprocess
import json
import os
import re
from app.config import (
    NUCLEI_BIN,
    TEMPLATES_DIR,
    NUCLEI_TIMEOUT,
    NUCLEI_RATE_LIMIT,
    logger,
)


class NucleiService:
    """Service untuk menjalankan Nuclei scanner."""

    def __init__(self):
        self.nuclei_bin = NUCLEI_BIN
        self.templates_dir = TEMPLATES_DIR
        self.timeout = NUCLEI_TIMEOUT
        self.rate_limit = NUCLEI_RATE_LIMIT

    def validate_target(self, url: str) -> bool:
        """
        Validasi URL target untuk mencegah SSRF dan command injection.
        Hanya izinkan http:// dan https:// scheme.
        """
        if not url or not isinstance(url, str):
            return False

        url = url.strip()

        # Harus dimulai dengan http:// atau https://
        if not re.match(r"^https?://", url, re.IGNORECASE):
            return False

        # Blokir karakter berbahaya (command injection)
        dangerous_chars = [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">", "\n", "\r"]
        for char in dangerous_chars:
            if char in url:
                return False

        return True

    def list_templates(self) -> list[dict]:
        """
        List semua template OJS yang tersedia.
        Return list of dict dengan info setiap template.
        """
        templates = []

        if not os.path.isdir(self.templates_dir):
            logger.warning(f"Templates directory not found: {self.templates_dir}")
            return templates

        for filename in sorted(os.listdir(self.templates_dir)):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(self.templates_dir, filename)
                template_info = self._parse_template_info(filepath)
                templates.append(template_info)

        return templates

    def run_scan(self, target_url: str, scan_profile: str = "general") -> dict:
        """
        Jalankan Nuclei scan terhadap target.

        Args:
            target_url: URL target yang akan di-scan
            scan_profile: "general" (OJS + Common Vulns) atau "ojs_only" (OJS khusus)

        Returns:
            dict dengan keys: findings, raw_output, errors, stats
        """
        if not self.validate_target(target_url):
            return {
                "findings": [],
                "raw_output": "",
                "errors": ["URL target tidak valid. Gunakan format http:// atau https://"],
                "stats": {"total": 0},
            }

        # Build command args (list-based, BUKAN shell=True)
        cmd = [
            self.nuclei_bin,
            "-target", target_url,
            "-jsonl",                        # Output JSON Lines
            "-no-color",                     # Tanpa ANSI colors
            "-rate-limit", str(self.rate_limit),
            "-timeout", "10",                # Per-request timeout
            "-retries", "1",
            "-duc",                          # Skip update check
            "-stats",                        # Enable progress logging
            "-si", "5",                      # Log progress every 5 seconds
        ]

        if scan_profile == "ojs_only":
            # Hanya gunakan folder templates OJS kita
            cmd.extend(["-t", self.templates_dir])
        else:
            # Gunakan folder templates OJS kita + subdirektori terpilih dari default Nuclei templates.
            # Tidak pakai -as (memfilter via Wappalyzer, OJS sering tidak dikenali).
            # Tidak pakai -severity (ikut memfilter OJS templates sendiri).
            # Tambah hanya subdirektori spesifik agar tidak interferensi dengan ribuan template.
            cmd.extend(["-t", self.templates_dir])
            default_base = os.path.expanduser("~/nuclei-templates")
            for subdir in ["http/cves", "http/exposures", "http/misconfiguration", "http/vulnerabilities"]:
                subdir_path = os.path.join(default_base, subdir)
                if os.path.isdir(subdir_path):
                    cmd.extend(["-t", subdir_path])

        logger.info(f"Running Nuclei scan on {target_url} with profile: {scan_profile}")
        logger.debug(f"Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            raw_output = result.stdout
            raw_errors = result.stderr

            # Parse JSONL output
            findings = self._parse_jsonl_output(raw_output)

            # Log errors jika ada (tapi Nuclei sering output info ke stderr)
            if raw_errors:
                logger.debug(f"Nuclei stderr: {raw_errors[:500]}")

            logger.info(f"Scan completed. Found {len(findings)} findings.")

            return {
                "findings": findings,
                "raw_output": raw_output,
                "errors": [],
                "stats": {
                    "total": len(findings),
                    "by_severity": self._count_by_severity(findings),
                },
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out after {self.timeout}s")
            return {
                "findings": [],
                "raw_output": "",
                "errors": [f"Scan timeout setelah {self.timeout} detik"],
                "stats": {"total": 0},
            }

        except FileNotFoundError:
            logger.error(f"Nuclei binary not found at {self.nuclei_bin}")
            return {
                "findings": [],
                "raw_output": "",
                "errors": [f"Nuclei binary tidak ditemukan di {self.nuclei_bin}"],
                "stats": {"total": 0},
            }

        except Exception as e:
            logger.error(f"Nuclei scan error: {e}")
            return {
                "findings": [],
                "raw_output": "",
                "errors": [str(e)],
                "stats": {"total": 0},
            }

    def _resolve_templates(self, template_names: list[str] = None) -> list[str]:
        """Resolve nama template ke path file lengkap."""
        if not template_names or "all" in template_names:
            return []  # Kosong = gunakan seluruh folder

        paths = []
        for name in template_names:
            # Coba dengan dan tanpa .yaml extension
            for ext in ["", ".yaml", ".yml"]:
                candidate = os.path.join(self.templates_dir, f"{name}{ext}")
                if os.path.isfile(candidate):
                    paths.append(candidate)
                    break
            else:
                logger.warning(f"Template not found: {name}")

        return paths

    def _normalize_list_field(self, value) -> str:
        """Nuclei v3 returns cve-id/cwe-id as list; normalize to comma-separated string."""
        if isinstance(value, list):
            return ", ".join(str(v) for v in value if v)
        return str(value) if value else ""

    def _parse_jsonl_output(self, raw_output: str) -> list[dict]:
        """Parse Nuclei JSONL output menjadi list of finding dicts."""
        findings = []

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append(self._normalize_finding(finding))
            except json.JSONDecodeError:
                logger.debug(f"Skipping non-JSON line: {line[:100]}")
                continue

        return findings

    def _normalize_finding(self, raw: dict) -> dict:
        """
        Normalize Nuclei finding ke format internal yang konsisten.
        Nuclei output format bisa bervariasi antar versi.
        """
        info = raw.get("info", {})
        classification = info.get("classification", {})

        return {
            "template_id": raw.get("template-id", raw.get("templateID", "")),
            "template_name": info.get("name", ""),
            "severity": info.get("severity", "unknown"),
            "description": info.get("description", ""),
            "host": raw.get("host", ""),
            "matched_at": raw.get("matched-at", raw.get("matched", "")),
            "matcher_name": raw.get("matcher-name", ""),
            "extracted_results": raw.get("extracted-results", []),
            "curl_command": raw.get("curl-command", ""),
            "type": raw.get("type", "http"),
            "cve_id": self._normalize_list_field(classification.get("cve-id", "")),
            "cwe_id": self._normalize_list_field(classification.get("cwe-id", "")),
            "cvss_score": classification.get("cvss-score", 0),
            "cvss_metrics": classification.get("cvss-metrics", ""),
            "tags": info.get("tags", []),
            "reference": info.get("reference", []),
            "timestamp": raw.get("timestamp", ""),
        }

    def _count_by_severity(self, findings: list[dict]) -> dict:
        """Hitung jumlah findings per severity level."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        for f in findings:
            severity = f.get("severity", "unknown").lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["unknown"] += 1
        return counts

    def _parse_template_info(self, filepath: str) -> dict:
        """Extract metadata dari file template YAML (tanpa dependency yaml parser)."""
        info = {
            "filename": os.path.basename(filepath),
            "id": "",
            "name": "",
            "severity": "",
            "description": "",
        }

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read(2000)  # Baca header saja

            # Simple regex parsing (avoid yaml dependency)
            id_match = re.search(r"^id:\s*(.+)$", content, re.MULTILINE)
            if id_match:
                info["id"] = id_match.group(1).strip()

            name_match = re.search(r"^\s+name:\s*(.+)$", content, re.MULTILINE)
            if name_match:
                info["name"] = name_match.group(1).strip()

            severity_match = re.search(r"^\s+severity:\s*(.+)$", content, re.MULTILINE)
            if severity_match:
                info["severity"] = severity_match.group(1).strip()

        except Exception as e:
            logger.debug(f"Error parsing template {filepath}: {e}")

        return info
