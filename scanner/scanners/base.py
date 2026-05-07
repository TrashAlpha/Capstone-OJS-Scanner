"""
modules/base.py
Kelas dasar untuk semua modul scanner.
Setiap modul WAJIB mengextend ScannerModule dan override metode run().
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
#from utils.logger import log


@dataclass
class Finding:
    """
    Representasi satu temuan kerentanan.
    Semua modul harus menghasilkan list Finding.
    """
    title:       str
    severity:    str          # critical | high | medium | low | info
    description: str
    evidence:    str          # bukti konkret (URL, header, response snippet)
    module:      str          # nama modul yang menemukan
    cve:         Optional[str] = None
    remediation: Optional[str] = None
    url:         Optional[str] = None
    extra:       dict         = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence,
            "module":      self.module,
            "cve":         self.cve,
            "remediation": self.remediation,
            "url":         self.url,
            "extra":       self.extra,
        }


class ScannerModule(ABC):
    """
    Abstract base class untuk semua modul scanner OJS.

    Cara pakai:
        class MyScanner(ScannerModule):
            def run(self, **kwargs) -> dict:
                findings = []
                # ... logika scan ...
                findings.append(Finding(
                    title="Judul Temuan",
                    severity="high",
                    description="Penjelasan",
                    evidence="https://...",
                    module=self.name
                ))
                return self.result(findings)
    """

    name: str = "base_module"

    def __init__(self, target_url: str, session=None):
        self.target_url = target_url.rstrip('/')
        self.session = session # Penting untuk Orang 3 (Internal Logic)

    def result(self, findings: list[Finding], raw: dict = None) -> dict:
        """Helper: bungkus findings jadi format standar yang dipakai pipeline."""
        return {
            "module":   self.name,
            "findings": [f.to_dict() for f in findings],
            "raw":      raw or {}
        }

    @abstractmethod
    def run(self, **kwargs) -> dict:
        """Jalankan scan. Return dict dari self.result()."""
        ...
