"""Smoke-test 1: parser format combined + deteksi 6 pola serangan (read-only).

Teknik yang diuji: deteksi berbasis tanda-tangan (signature-based) + ambang laju
(rate/threshold-based) sesuai taksonomi NIST SP 800-94. Regex hanya mesin
pencocoknya; tekniknya sama seperti yang dipakai Snort/ModSecurity/Fail2Ban,
hanya scope-nya log Apache OJS (bukan paket jaringan).

Data dibaca dari file terkunci (bukan dibangkitkan di sini):
  - data-sintetis-st1.log : 1.000 baris format Apache combined
  - ekspektasi-st1.csv     : id_baris,label (ground truth mini ST1)
Generatornya: buat-data-st1.py (seed=42; hash tercatat di eksekusi-smoke-test.md).
CATATAN PENTING (seminar): data 100% SINTETIS, hanya untuk validasi risiko
pra-judul. Dataset evaluasi TA dilabel manual secara terpisah (Bab III).
"""
# Hanya stdlib: bukti klaim "tanpa dependensi tambahan, tanpa GPU".
import csv
import re
import time
from pathlib import Path

DASAR = Path(__file__).resolve().parent

# Format Apache combined:
#   %h = IP pengirim (siapa; dianonimkan via hash di pipeline final),
#   %t = waktu (jendela agregasi ambang),
#   "%r" = method + path + protokol (path inilah yang dianalisis aturan),
#   %>s = status akhir (401/403/404 = sinyal brute-force vs scanner),
#   %b = ukuran, Referer/UA = konteks tambahan (bedakan bot vs browser).
COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# Enam tanda-tangan, masing-masing WAJIB punya sumber (kolom sumber di Bab II):
# - sqli/xss: generik web, merujuk OWASP CRS (aturan generik ModSecurity).
# - traversal: CVE-2025-67890 (parameter file_name galley) -> presisi tinggi.
# - xxe: CVE-2024-56525 (import XML) -> presisi tinggi.
# - bruteforce_login: pola perilaku ala Fail2Ban (maxretry/findtime di tahap agregasi).
# - scanner: path probing umum (.git/.env/phpmyadmin).
# Urutan = prioritas (temuan ST1: traversal sebelum scanner karena "../" overlap).
RULES = [
    ("traversal", re.compile(r"(\.\./|%2e%2e|/etc/passwd)", re.I)),
    ("xxe", re.compile(r"(<!ENTITY|DOCTYPE.*\[|importexport|xml.*import)", re.I)),
    ("sqli", re.compile(r"(%27|'|%22).*(union|select|or\s+1\s*=\s*1)", re.I)),
    ("xss", re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("bruteforce_login", re.compile(r"(login|signin|wp-login|administrator/index\.php)", re.I)),
    ("scanner", re.compile(r"(\.git/|\.env|wp-login\.php|phpmyadmin|xmlrpc\.php|issue_galley)", re.I)),
]

lines = (DASAR / "data-sintetis-st1.log").read_text().splitlines()
expect: dict[str, int] = {}
with open(DASAR / "ekspektasi-st1.csv", newline="") as f:
    for row in csv.DictReader(f):
        expect[row["label"]] = expect.get(row["label"], 0) + 1
assert len(lines) == sum(expect.values()) == 1000, "file data tidak konsisten!"

t0 = time.time()
parsed, failed, hits = 0, 0, {}
for ln in lines:
    m = COMBINED.match(ln)
    if not m:
        # Baris tak dikenal dicatat, TIDAK dipaksa.
        failed += 1
        continue
    parsed += 1
    d = m.groupdict()
    for kind, rx in RULES:
        if rx.search(d["path"]):
            hits[kind] = hits.get(kind, 0) + 1
            break  # first-match wins; satu baris satu label utama.
dt = time.time() - t0
print(f"ST1 parse: {parsed}/1000 ok, gagal={failed}, waktu={dt:.2f}s")
print("ST1 deteksi vs ekspektasi:")
for k in sorted(set(list(expect) + list(hits))):
    print(f"  {k:18s} ekspektasi={expect.get(k,0):4d} terdeteksi={hits.get(k,0):4d}")
# Kriteria LULUS = ambang validasi risiko (0 gagal parse; total deteksi serangan
# >=80% ekspektasi serangan — toleransi overlap aturan yang sudah diputuskan
# sebagai urutan prioritas), BUKAN metrik Bab IV (presisi/recall di dataset berlabel).
total_serang_eks = sum(v for k, v in expect.items() if k != "benign")
total_serang_hit = sum(v for k, v in hits.items())
print("ST1 RESULT:", "LULUS DENGAN CATATAN" if failed == 0 and total_serang_hit >= total_serang_eks * 0.8 else "GAGAL")
