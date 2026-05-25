FROM pkpofficial/ojs:3_3_0-14

# =============================================================
# PATCH: Nonaktifkan getLatestVersion() di VersionCheck.inc.php
#
# OJS secara default memanggil http://pkp.sfu.ca/ojs/xml/ojs-version.xml
# setiap kali halaman admin dibuka untuk cek versi terbaru.
# Di environment lokal/Docker tanpa akses internet ke pkp.sfu.ca,
# ini menyebabkan GuzzleHttp Fatal Error → HTTP 500.
#
# Fix: Patch getLatestVersion() agar langsung return false
# tanpa mencoba fetch URL eksternal.
# =============================================================
RUN sed -i \
    's/static function getLatestVersion() {/static function getLatestVersion() {\n\t\treturn false; \/\/ Patched: disabled to prevent fatal error from unreachable pkp.sfu.ca/' \
    /var/www/html/lib/pkp/classes/site/VersionCheck.inc.php
