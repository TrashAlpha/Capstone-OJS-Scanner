"""
app/services/report_service.py
Menyusun final report JSON dari hasil Nuclei scan dan LLM analysis.
Report ini siap dikonsumsi oleh Dashboard Laravel dan Risk Engine.
"""

from datetime import datetime, timezone
from app.config import logger


class ReportService:
    """Service untuk menyusun final report."""

    def generate(
        self,
        target_url: str,
        scan_type: str,
        nuclei_results: dict,
        llm_analysis: dict,
        scan_duration: float = 0.0,
    ) -> dict:
        """
        Gabung semua data jadi final report.

        Args:
            target_url: URL yang di-scan
            scan_type: Tipe scan (full / nuclei_only)
            nuclei_results: Output dari NucleiService.run_scan()
            llm_analysis: Output dari LLMService.analyze()
            scan_duration: Durasi scan dalam detik

        Returns:
            dict final report yang siap di-return sebagai JSON
        """
        findings = nuclei_results.get("findings", [])
        severity_counts = nuclei_results.get("stats", {}).get("by_severity", {})

        report = {
            "target_url": target_url,
            "scan_type": scan_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(scan_duration, 2),

            # ── Ringkasan ──────────────────────────────────────
            "summary": {
                "total_findings": len(findings),
                "findings_count": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "info": severity_counts.get("info", 0),
                },
            },

            # ── Detail Nuclei findings (enriched dengan LLM remediation) ──
            "nuclei_results": self._enrich_findings(findings, llm_analysis),

            # ── Analisis LLM ───────────────────────────────────
            "llm_analysis": {
                "summary": llm_analysis.get("summary", ""),
                "risk_assessment": llm_analysis.get("risk_assessment", ""),
                "recommendations": llm_analysis.get("recommendations", []),
                "finding_analysis": llm_analysis.get("finding_analysis", []),
                "llm_failed": llm_analysis.get("llm_failed", False),
                "raw_response": llm_analysis.get("raw_response", ""),
            },

            # ── Error/warnings ─────────────────────────────────
            "errors": nuclei_results.get("errors", []),
        }

        logger.info(
            f"Report generated for {target_url}: "
            f"{len(findings)} findings, "
            f"risk={llm_analysis.get('risk_assessment', 'N/A')}"
        )

        return report

    def _enrich_findings(self, findings: list, llm_analysis: dict) -> list:
        """Merge remediation & impact dari LLM ke tiap finding, match by template_id."""
        fa_list = llm_analysis.get("finding_analysis", [])
        remediation_map = {
            fa.get("template_id", ""): fa
            for fa in fa_list
            if fa.get("template_id")
        }

        enriched = []
        for finding in findings:
            f = dict(finding)
            tid = f.get("template_id", "")
            if tid and tid in remediation_map:
                fa = remediation_map[tid]
                f["remediation"]    = fa.get("remediation", "")
                f["impact"]         = fa.get("impact", "")
                f["llm_risk_level"] = fa.get("risk_level", "")
            enriched.append(f)

        return enriched

    def generate_nuclei_only(
        self,
        target_url: str,
        nuclei_results: dict,
        scan_duration: float = 0.0,
    ) -> dict:
        """
        Generate report tanpa LLM analysis (nuclei_only mode).
        """
        findings = nuclei_results.get("findings", [])
        severity_counts = nuclei_results.get("stats", {}).get("by_severity", {})

        return {
            "target_url": target_url,
            "scan_type": "external_nuclei",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(scan_duration, 2),
            "summary": {
                "total_findings": len(findings),
                "findings_count": {
                    "critical": severity_counts.get("critical", 0),
                    "high": severity_counts.get("high", 0),
                    "medium": severity_counts.get("medium", 0),
                    "low": severity_counts.get("low", 0),
                    "info": severity_counts.get("info", 0),
                },
            },
            "nuclei_results": findings,
            "errors": nuclei_results.get("errors", []),
        }
