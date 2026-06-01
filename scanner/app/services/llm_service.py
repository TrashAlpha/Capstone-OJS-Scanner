"""
app/services/llm_service.py
Integrasi LLM (Gemini 3.5 Flash) untuk analisis hasil scan Nuclei.
Menghasilkan summary, risk assessment, dan rekomendasi dalam Bahasa Indonesia.
"""

import json
import re
import time
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

    def _call_llm_with_retry(self, prompt: str, max_retries: int = 3, base_delay: float = 2.0) -> str:
        """Call LLM API with exponential backoff retry. Raises last exception if all attempts fail."""
        last_exc: Exception = RuntimeError("LLM not called")
        for attempt in range(1, max_retries + 1):
            try:
                client = self._get_client()
                response = client.models.generate_content(model=self.model, contents=prompt)
                logger.info(f"LLM call succeeded on attempt {attempt}/{max_retries}")
                return response.text
            except Exception as e:
                last_exc = e
                logger.warning(f"LLM call attempt {attempt}/{max_retries} failed: {e}")
                if attempt < max_retries:
                    sleep_sec = base_delay * attempt  # 2s, 4s
                    logger.info(f"Retrying in {sleep_sec}s...")
                    time.sleep(sleep_sec)
        raise last_exc

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
            return self._fallback_analysis(nuclei_results, llm_failed=True)

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
            raw_text = self._call_llm_with_retry(prompt)
            logger.info("LLM analysis completed successfully")
            return self._parse_llm_response(raw_text)
        except Exception as e:
            logger.error(f"LLM analysis failed after all retries: {e}")
            return self._fallback_analysis(nuclei_results, llm_failed=True)

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
        cleaned = raw_text.strip()

        # Strategi 1: strip markdown code block (```json ... ``` atau ``` ... ```)
        if "```" in cleaned:
            cleaned_try = re.sub(r"```(?:json)?\s*", "", cleaned).replace("```", "").strip()
        else:
            cleaned_try = cleaned

        # Strategi 2: ekstrak JSON object pertama menggunakan regex (fallback jika ada teks di luar)
        json_candidates = [cleaned_try, cleaned]
        match = re.search(r"\{[\s\S]*\}", cleaned_try)
        if match:
            json_candidates.insert(0, match.group(0))

        for candidate in json_candidates:
            try:
                result = json.loads(candidate)
                if isinstance(result, dict):
                    result["raw_response"] = raw_text
                    return result
            except json.JSONDecodeError:
                continue

        logger.warning("Failed to parse LLM response as JSON, storing as summary")
        return {
            "summary": raw_text,
            "risk_assessment": "",
            "recommendations": [],
            "raw_response": raw_text,
        }

    def _fallback_analysis(self, findings: list[dict], llm_failed: bool = False) -> dict:
        """
        Analisis fallback jika LLM tidak tersedia atau gagal setelah retry.
        Menghasilkan summary sederhana berdasarkan data findings.
        """
        if not findings:
            return {
                "summary": "Tidak ditemukan kerentanan dari hasil scan.",
                "risk_assessment": "RENDAH",
                "recommendations": ["Lakukan pemindaian berkala."],
                "llm_failed": llm_failed,
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

        raw_response_note = (
            "Analisis AI gagal setelah beberapa percobaan — analisis dilakukan secara manual berdasarkan data temuan."
            if llm_failed else
            "(Fallback analysis — LLM tidak tersedia)"
        )

        return {
            "summary": " ".join(summary_parts),
            "risk_assessment": risk,
            "recommendations": recommendations,
            "llm_failed": llm_failed,
            "raw_response": raw_response_note,
        }

    # ── Internal scan analysis ─────────────────────────────────

    def analyze_internal(self, findings: list[dict]) -> dict:
        """
        Analisis hasil internal (authenticated) scan menggunakan LLM.
        Findings berformat: {title, severity, description, evidence, remediation, cve, module}
        """
        if not self.api_key:
            logger.warning("LLM_API_KEY not set, returning fallback analysis for internal scan")
            return self._fallback_analysis_internal(findings, llm_failed=True)

        if not findings:
            return {
                "summary": "Tidak ditemukan kerentanan dari hasil scan internal.",
                "risk_assessment": "RENDAH",
                "recommendations": ["Tetap lakukan pemindaian berkala."],
                "finding_analysis": [],
                "raw_response": "",
            }

        prompt = self._build_prompt_internal(findings)
        try:
            raw_text = self._call_llm_with_retry(prompt)
            logger.info("LLM internal analysis completed successfully")
            return self._parse_llm_response(raw_text)
        except Exception as e:
            logger.error(f"LLM internal analysis failed after all retries: {e}")
            return self._fallback_analysis_internal(findings, llm_failed=True)

    def _build_prompt_internal(self, findings: list[dict]) -> str:
        """Bangun prompt untuk LLM berdasarkan internal scan findings."""
        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += f"""
--- Temuan #{i} ---
Nama: {f.get('title', 'N/A')}
Severity: {f.get('severity', 'N/A')}
Modul: {f.get('module', 'N/A')}
CWE/CVE: {f.get('cve', 'N/A')}
Deskripsi: {f.get('description', 'N/A')}
Evidence: {str(f.get('evidence', 'N/A'))[:300]}
Saran Perbaikan (awal): {f.get('remediation', 'N/A')}
URL: {f.get('url', 'N/A')}
"""

        return f"""Kamu adalah seorang ahli keamanan siber yang menganalisis hasil pemindaian kerentanan authenticated pada sistem Open Journal Systems (OJS).

Berikut adalah hasil scan internal (authenticated) yang menemukan kerentanan:

{findings_text}

Berikan analisis dalam Bahasa Indonesia dengan format JSON berikut (HANYA output JSON, tanpa markdown code block):

{{
  "summary": "Ringkasan keseluruhan kondisi keamanan dalam 2-3 paragraf. Jelaskan temuan utama dan dampaknya.",
  "risk_assessment": "Penilaian risiko keseluruhan (KRITIS/TINGGI/SEDANG/RENDAH) dengan penjelasan singkat.",
  "recommendations": [
    "Rekomendasi 1 yang spesifik dan actionable",
    "Rekomendasi 2 ...",
    "Rekomendasi 3 ..."
  ],
  "finding_analysis": [
    {{
      "title": "judul temuan persis seperti di atas",
      "risk_level": "KRITIS/TINGGI/SEDANG/RENDAH",
      "impact": "Dampak konkret jika dieksploitasi",
      "remediation": "Langkah perbaikan spesifik dan actionable"
    }}
  ]
}}

Penting:
- Gunakan Bahasa Indonesia yang profesional
- Berikan rekomendasi yang spesifik untuk OJS
- Prioritaskan berdasarkan severity
- Jangan gunakan markdown code block, langsung output JSON
"""

    def _fallback_analysis_internal(self, findings: list[dict], llm_failed: bool = False) -> dict:
        """Fallback analysis untuk internal scan jika LLM tidak tersedia atau gagal setelah retry."""
        if not findings:
            return {
                "summary": "Tidak ditemukan kerentanan dari hasil scan internal.",
                "risk_assessment": "RENDAH",
                "recommendations": ["Lakukan pemindaian berkala."],
                "finding_analysis": [],
                "llm_failed": llm_failed,
                "raw_response": "",
            }

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        if severity_counts["critical"] > 0:
            risk = "KRITIS"
        elif severity_counts["high"] > 0:
            risk = "TINGGI"
        elif severity_counts["medium"] > 0:
            risk = "SEDANG"
        else:
            risk = "RENDAH"

        summary_parts = [f"Ditemukan total {len(findings)} temuan kerentanan dari scan internal (authenticated)."]
        if severity_counts["critical"] > 0:
            summary_parts.append(f"Terdapat {severity_counts['critical']} temuan KRITIS yang memerlukan penanganan segera.")
        if severity_counts["high"] > 0:
            summary_parts.append(f"Terdapat {severity_counts['high']} temuan severity HIGH.")

        # Gunakan remediation yang sudah ada dari scanner module sebagai finding_analysis
        finding_analysis = [
            {
                "title": f.get("title", "Unknown"),
                "risk_level": f.get("severity", "info").upper(),
                "impact": f.get("description", "Lihat deskripsi temuan."),
                "remediation": f.get("remediation") or "Lakukan review manual dan perbaiki konfigurasi.",
            }
            for f in findings
            if f.get("severity", "info").lower() in ("critical", "high", "medium")
        ]

        recommendations = [
            "Perbaiki konfigurasi keamanan OJS sesuai temuan yang ditemukan.",
            "Ganti password default dan kredensial yang lemah segera.",
            "Perbarui OJS ke versi terbaru untuk menutup kerentanan yang diketahui.",
            "Lakukan scan ulang setelah semua perbaikan diterapkan.",
        ]
        if severity_counts["critical"] > 0:
            recommendations.insert(0, "SEGERA tangani temuan KRITIS — risiko eksploitasi sangat tinggi.")

        raw_response_note = (
            "Analisis AI gagal setelah beberapa percobaan — analisis dilakukan secara manual berdasarkan data temuan."
            if llm_failed else
            "(Fallback analysis — LLM tidak tersedia)"
        )

        return {
            "summary": " ".join(summary_parts),
            "risk_assessment": risk,
            "recommendations": recommendations,
            "finding_analysis": finding_analysis,
            "llm_failed": llm_failed,
            "raw_response": raw_response_note,
        }
