"""
app/services/llm_service.py
Integrasi LLM (Gemini 3.5 Flash) untuk analisis hasil scan Nuclei.
Menghasilkan summary, risk assessment, dan rekomendasi dalam Bahasa Indonesia.
"""

import json
from app.config import LLM_API_KEY, LLM_MODEL, LLM_PROVIDER, logger


class LLMService:
    """Service untuk analisis hasil scan menggunakan Gemini 3.5 Flash."""

    def __init__(self):
        self.api_key = LLM_API_KEY
        self.model = LLM_MODEL
        self.provider = LLM_PROVIDER
        self._client = None

    def _get_client(self):
        """Lazy initialization untuk Gemini client."""
        if self._client is None:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
                logger.info(f"LLM client initialized: {self.provider}/{self.model}")
            except ImportError:
                logger.error("google-genai package not installed")
                raise
            except Exception as e:
                logger.error(f"Failed to initialize LLM client: {e}")
                raise
        return self._client

    def analyze(self, nuclei_results: list[dict]) -> dict:
        """
        Analisis hasil scan Nuclei menggunakan LLM.

        Args:
            nuclei_results: List of normalized finding dicts dari NucleiService

        Returns:
            dict dengan keys: summary, risk_assessment, recommendations, raw_response
        """
        if not self.api_key:
            logger.warning("LLM_API_KEY not set, returning fallback analysis")
            return self._fallback_analysis(nuclei_results)

        if not nuclei_results:
            return {
                "summary": "Tidak ditemukan kerentanan dari hasil scan Nuclei.",
                "risk_assessment": "RENDAH — Tidak ada temuan yang terdeteksi.",
                "recommendations": [
                    "Tetap lakukan pemindaian berkala.",
                    "Pastikan OJS selalu di-update ke versi terbaru.",
                ],
                "raw_response": "",
            }

        prompt = self._build_prompt(nuclei_results)

        try:
            client = self._get_client()
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            raw_text = response.text
            logger.info("LLM analysis completed successfully")

            return self._parse_llm_response(raw_text)

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._fallback_analysis(nuclei_results)

    def _build_prompt(self, findings: list[dict]) -> str:
        """Bangun prompt terstruktur untuk LLM analysis."""

        # Format findings jadi teks ringkas
        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += f"""
--- Temuan #{i} ---
Template: {f.get('template_id', 'N/A')}
Nama: {f.get('template_name', 'N/A')}
Severity: {f.get('severity', 'N/A')}
CVE: {f.get('cve_id', 'N/A')}
CWE: {f.get('cwe_id', 'N/A')}
CVSS Score: {f.get('cvss_score', 'N/A')}
Deskripsi: {f.get('description', 'N/A')}
URL Match: {f.get('matched_at', 'N/A')}
Extracted: {json.dumps(f.get('extracted_results', []), ensure_ascii=False)}
"""

        prompt = f"""Kamu adalah seorang ahli keamanan siber yang menganalisis hasil pemindaian kerentanan pada sistem Open Journal Systems (OJS).

Berikut adalah hasil pemindaian menggunakan Nuclei scanner:

{findings_text}

Berikan analisis dalam Bahasa Indonesia dengan format JSON berikut (HANYA output JSON, tanpa markdown code block):

{{
  "summary": "Ringkasan keseluruhan kondisi keamanan target dalam 2-3 paragraf. Jelaskan temuan utama dan dampaknya.",
  "risk_assessment": "Penilaian risiko keseluruhan (KRITIS/TINGGI/SEDANG/RENDAH) dengan penjelasan singkat.",
  "recommendations": [
    "Rekomendasi 1 yang spesifik dan actionable",
    "Rekomendasi 2 ...",
    "Rekomendasi 3 ..."
  ],
  "finding_analysis": [
    {{
      "template_id": "id template",
      "risk_level": "KRITIS/TINGGI/SEDANG/RENDAH",
      "impact": "Dampak jika dieksploitasi",
      "remediation": "Langkah perbaikan spesifik"
    }}
  ]
}}

Penting:
- Gunakan Bahasa Indonesia yang profesional
- Berikan rekomendasi yang spesifik untuk OJS
- Prioritaskan berdasarkan severity dan exploitability
- Jangan gunakan markdown code block, langsung output JSON
"""
        return prompt

    def _parse_llm_response(self, raw_text: str) -> dict:
        """Parse response LLM ke format dict."""
        # Coba parse sebagai JSON langsung
        try:
            # Bersihkan markdown code block jika ada
            cleaned = raw_text.strip()
            if cleaned.startswith("```"):
                # Remove ```json dan ```
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)

            result = json.loads(cleaned)
            result["raw_response"] = raw_text
            return result

        except json.JSONDecodeError:
            logger.warning("Failed to parse LLM response as JSON, using raw text")
            return {
                "summary": raw_text,
                "risk_assessment": "Lihat summary untuk detail.",
                "recommendations": [],
                "raw_response": raw_text,
            }

    def _fallback_analysis(self, findings: list[dict]) -> dict:
        """
        Analisis fallback jika LLM tidak tersedia.
        Menghasilkan summary sederhana berdasarkan data findings.
        """
        if not findings:
            return {
                "summary": "Tidak ditemukan kerentanan dari hasil scan.",
                "risk_assessment": "RENDAH",
                "recommendations": ["Lakukan pemindaian berkala."],
                "raw_response": "",
            }

        # Hitung severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cves_found = []

        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            cve = f.get("cve_id", "")
            if cve:
                cves_found.append(cve)

        # Tentukan risk level
        if severity_counts["critical"] > 0:
            risk = "KRITIS"
        elif severity_counts["high"] > 0:
            risk = "TINGGI"
        elif severity_counts["medium"] > 0:
            risk = "SEDANG"
        else:
            risk = "RENDAH"

        summary_parts = [
            f"Ditemukan total {len(findings)} temuan kerentanan.",
        ]

        if severity_counts["critical"] > 0:
            summary_parts.append(
                f"Terdapat {severity_counts['critical']} temuan KRITIS yang memerlukan penanganan segera."
            )
        if severity_counts["high"] > 0:
            summary_parts.append(
                f"Terdapat {severity_counts['high']} temuan severity HIGH."
            )
        if cves_found:
            summary_parts.append(
                f"CVE yang terdeteksi: {', '.join(set(cves_found))}."
            )

        recommendations = [
            "Update OJS ke versi terbaru dari https://pkp.sfu.ca/ojs/ojs_download/",
            "Review dan perbaiki konfigurasi keamanan server.",
            "Lakukan pemindaian ulang setelah perbaikan diterapkan.",
        ]

        if severity_counts["critical"] > 0:
            recommendations.insert(0, "SEGERA tangani temuan KRITIS — risiko eksploitasi sangat tinggi.")

        return {
            "summary": " ".join(summary_parts),
            "risk_assessment": risk,
            "recommendations": recommendations,
            "raw_response": "(Fallback analysis — LLM tidak tersedia)",
        }
