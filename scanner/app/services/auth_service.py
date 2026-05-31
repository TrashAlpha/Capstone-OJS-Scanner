"""
app/services/auth_service.py
Manajemen autentikasi ke website OJS untuk internal scanner.
Menggunakan requests.Session agar cookie OJSID otomatis disertakan di setiap request.
"""

import re
import requests
from app.config import logger


class OJSAuthService:
    """Service untuk login ke OJS dan mengelola sesi terotentikasi."""

    LOGIN_TIMEOUT = 15
    PROBE_TIMEOUT = 10

    def login(self, target_url: str, username: str, password: str) -> requests.Session | None:
        """
        Login ke OJS dan kembalikan Session yang sudah terotentikasi.

        Flow:
        1. GET /login → ambil CSRF token
        2. POST /login/signIn dengan username, password, csrfToken
        3. Verifikasi login berhasil (tidak redirect kembali ke /login)

        Returns:
            requests.Session jika login berhasil, None jika gagal.
        """
        base = target_url.rstrip("/")
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (OJS-Security-Scanner/2.0)",
        })

        # Step 1: Ambil halaman login untuk CSRF token
        login_url = f"{base}/index.php/index/login"
        try:
            resp = session.get(login_url, timeout=self.LOGIN_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            logger.error(f"[Auth] Gagal mengakses halaman login: {e}")
            return None

        csrf_token = self._extract_csrf_token(resp.text)
        if not csrf_token:
            logger.warning("[Auth] CSRF token tidak ditemukan di halaman login")

        # Step 2: Submit form login
        sign_in_url = f"{base}/index.php/index/login/signIn"
        form_data = {
            "username": username,
            "password": password,
            "remember": "1",
        }
        if csrf_token:
            form_data["csrfToken"] = csrf_token

        try:
            resp = session.post(
                sign_in_url,
                data=form_data,
                timeout=self.LOGIN_TIMEOUT,
                allow_redirects=True,
            )
        except requests.RequestException as e:
            logger.error(f"[Auth] Gagal POST ke signIn: {e}")
            return None

        # Step 3: Verifikasi login — jika berhasil, tidak akan redirect ke /login
        final_url = resp.url.lower()
        if "login" in final_url and "signout" not in final_url:
            logger.warning(f"[Auth] Login gagal untuk user '{username}' — masih di halaman login")
            return None

        # Cek juga apakah ada indikasi error di body
        if "incorrect password" in resp.text.lower() or "invalid username" in resp.text.lower():
            logger.warning(f"[Auth] Login gagal — kredensial tidak valid")
            return None

        logger.info(f"[Auth] Login berhasil untuk user '{username}'")
        return session

    def get_role(self, session: requests.Session, target_url: str) -> str:
        """
        Deteksi role user dari session yang aktif.

        Probe ke admin panel — hanya admin yang mendapat 200.
        Returns: "admin" | "editor" | "author" | "unknown"
        """
        base = target_url.rstrip("/")

        # Cek admin access
        try:
            resp = session.get(
                f"{base}/index.php/index/admin",
                timeout=self.PROBE_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                return "admin"
        except requests.RequestException:
            pass

        # Cek editor/manager access
        try:
            resp = session.get(
                f"{base}/index.php/index/manageJournal",
                timeout=self.PROBE_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                return "editor"
        except requests.RequestException:
            pass

        # Cek author access (submission dashboard)
        try:
            resp = session.get(
                f"{base}/index.php/index/submissions",
                timeout=self.PROBE_TIMEOUT,
                allow_redirects=False,
            )
            if resp.status_code == 200:
                return "author"
        except requests.RequestException:
            pass

        return "unknown"

    def is_valid(self, session: requests.Session, target_url: str) -> bool:
        """Verifikasi apakah session masih aktif (belum expired)."""
        base = target_url.rstrip("/")
        try:
            resp = session.get(
                f"{base}/index.php/index/user/profile",
                timeout=self.PROBE_TIMEOUT,
                allow_redirects=False,
            )
            # Session valid jika tidak di-redirect ke halaman login
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _extract_csrf_token(self, html: str) -> str | None:
        """Ekstrak CSRF token dari form HTML OJS."""
        patterns = [
            r'<input[^>]+name=["\']csrfToken["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']csrfToken["\']',
            r'"csrfToken"\s*:\s*"([^"]+)"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
