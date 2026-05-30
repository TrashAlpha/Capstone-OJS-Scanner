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

            # ── Detail Nuclei findings ─────────────────────────
            "nuclei_results": findings,

            # ── Analisis LLM ───────────────────────────────────
            "llm_analysis": {
                "summary": llm_analysis.get("summary", ""),
                "risk_assessment": llm_analysis.get("risk_assessment", ""),
                "recommendations": llm_analysis.get("recommendations", []),
                "finding_analysis": llm_analysis.get("finding_analysis", []),
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
            "scan_type": "nuclei_only",
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
