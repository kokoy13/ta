# Penjelasan Kode `smoke1_parser.py` (ST1)

File: `docs/smoke-test/smoke1_parser.py`
Data uji (terkunci): `docs/smoke-test/data-sintetis-st1.log` (1.000 baris)
+ `docs/smoke-test/ekspektasi-st1.csv` (ground truth mini).
Generator: `docs/smoke-test/buat-data-st1.py` (`seed=42`; hash tercatat di
`eksekusi-smoke-test.md`). Prinsip: generator boleh berevolusi, file data
dikunci — sama seperti “set uji dikunci”.
Teknik yang diuji: **deteksi berbasis tanda-tangan (signature-based) + ambang
laju (rate/threshold-based)** sesuai taksonomi NIST SP 800-94. Regex hanya
mesin pencocoknya — tekniknya sama seperti Snort/ModSecurity/Fail2Ban, hanya
scope-nya log Apache OJS (bukan paket jaringan).

## Tujuan uji

Menjawab sebelum judul diajukan: *“Bisakah format log Virtualmin diparse dan
pola serangan dideteksi dengan regex tanpa GPU?”* Hasil: parse 1000/1000 OK
(0,01 dtk). Ini **validasi risiko, bukan evaluasi TA** — datanya 100% sintetis;
metrik presisi/recall diukur nanti di dataset berlabel (Bab III–IV).

## Cara menjalankan

```text
python docs/smoke-test/smoke1_parser.py
```

Output yang diharapkan: `ST1 parse: 1000/1000 ok, gagal=0`,
perbandingan ekspektasi vs terdeteksi per pola, dan baris `ST1 RESULT`.
Kriteria LULUS = 0 gagal parse + tiap pola ≥80% (ambang validasi risiko).

## Peta komponen ST1

```text
Baris log format combined (Virtualmin)
        |
        v
[1. COMBINED regex] pecah jadi ip/time/method/path/status/ua
  - path  -> dianalisis aturan (kolom yang penting)
  - status -> sinyal 401/403/404 (brute-force vs scanner)
  - baris tak dikenal -> dicatat gagal, TIDAK dipaksa
        |
        v
[2. RULES: 6 tanda-tangan BERURUTAN PRIORITAS]
  traversal -> xxe -> sqli -> xss -> bruteforce_login -> scanner
  (first-match wins; satu baris satu label utama)
        |
        v
[3. Pencacah hits vs ekspektasi + timer]
        |
        v
[4. Keputusan LULUS/GAGAL + temuan overlap aturan]
```

## Bedah per blok kode

1. **Impor (stdlib saja)** — `re, random, time`. Bukti klaim “tanpa
   dependensi tambahan, tanpa GPU”.
2. **`COMBINED`** — regex format Apache `combined`
   (`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`). Grup bernama:
   `ip` (siapa; dianonimkan via hash di pipeline final), `time` (kapan;
   jendela agregasi ambang), `method`+`path` (diakses apa; kolom analisis),
   `status` (hasil; 401/403/404 = sinyal), `ua` (konteks bot vs browser).
3. **`RULES`** — 6 tanda-tangan, tiap pola wajib punya sumber (lihat tabel
   Bab II 2.1): sqli/xss generik (OWASP CRS), traversal (CVE-2025-67890,
   parameter `file_name` galley), xxe (CVE-2024-56525, import XML),
   bruteforce_login (perilaku ala Fail2Ban `maxretry`/`findtime`),
   scanner (path probing umum). Kelemahan sadar: regex buta konteks
   (kata benign bisa cocok) dan buta varian encoding — dimitigasi
   normalisasi/decode + korelasi status + ambang agregat + verifikasi manusia.
4. **Data sintetis** — `seed(42)` agar reproduksibel; 10 path benign vs 7 path
   serang; 1.000 baris dengan 30% serangan + status realistis per jenis.
5. **Loop uji** — tiap baris di-`match`; gagal parse dihitung (bukan error);
   tiap path dicek ke 6 aturan berurutan, cocok pertama menang lalu `break`.
6. **Laporan** — cetak parse OK/gagal/waktu, tabel ekspektasi vs terdeteksi,
   keputusan LULUS/GAGAL.

## Temuan ST1 dan keputusan desain turunannya

Pola `../` cocok di aturan `traversal` SEKALIGUS `scanner` (85 vs 41 dan
43 vs 87 pada run 7 Okt 2026). Ini artefak overlap aturan, bukan kegagalan
parser. Keputusan desain: **aturan dievaluasi berurutan prioritas**
(traversal sebelum scanner) + satu baris satu label utama + kolom sumber per
aturan di proposal. Status ST1: **LULUS dengan catatan** (catatan ini).
