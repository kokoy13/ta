# Dokumentasi Eksekusi Smoke-Test (Validasi Risiko Pra-Pengajuan)

Judul final: **Pengembangan dan Implementasi Security Operations Center
Berbasis Log untuk Analisis Keamanan Open Journal Systems Menggunakan MCP
Server dan AI Agent dengan Metode Behavior-Based Detection**

Metode: **Behavior-Based Detection dengan Rule-Based Correlation dan
Threshold Analysis**

Tanggal: ST1–ST3 7 Oktober 2026; ST4–ST6 22–23 Oktober 2026.

Lingkungan ST4–ST6: Windows, Python 3.15.0, tanpa Wazuh, tanpa endpoint LLM.
ST1–ST3 dijalankan pada Windows, Python 3.13.7, `mcp` SDK 1.27.0.

Cakupan implementasi TA: **SOC teknis berbasis log skala terbatas dengan Wazuh
sebagai satu-satunya platform deteksi**. Suricata/IDS jaringan, SOAR,
ticketing, case management, dan tim 24/7 tidak termasuk. Implementasi
direncanakan pada instalasi OJS 3.x produksi instansi mitra dengan izin
tertulis dan akses log read-only. Smoke test ST1–ST6 memakai data sintetis;
tidak ada log produksi yang dipakai pada tahap ini.

Verifikasi ulang setelah perubahan judul/scope (23 Oktober 2026):
**ST4 PREFLIGHT PASS; ST5 PASS; ST6 PASS**; `py_compile` dan `bash -n` OK.

## ST1 — Parser format `combined` + deteksi 6 pola (1.000 baris)

* Lokasi: `docs/smoke-test/smoke-test1/`.
* Hasil: parse **1000/1000 OK, gagal 0, waktu 0,01 dtk**.
* Deteksi vs ekspektasi: sqli 42/42, xss 45/45, xxe 38/38,
  bruteforce_login 39/39 tepat; traversal 85 vs 41 dan scanner 43 vs 87 karena
  pola `../` cocok di kedua aturan (artefak data sintetis, bukan kegagalan parser).
* Keputusan desain: aturan evaluasi **berurutan prioritas** (traversal sebelum
  scanner) + satu baris hanya boleh satu label utama.
* Status: **LULUS dengan catatan** (catatan sudah masuk desain).

## ST2 — Satu tool MCP `rekap_harian` via FastMCP

* Lokasi: `docs/smoke-test/smoke-test2/`.
* Hasil: tool terdaftar (`list_tools` mengembalikan `rekap_harian`),
  output agregat benar (total 32.667), audit hash argumen tercetak,
  tidak ada IP mentah tersimpan.
* ST2b round-trip: initialize → `tools/list` → `tools/call rekap_harian`
  via stdio → total 32.667.
* Status: **LULUS** — jembatan dua arah terbukti.

## ST3 — Import 100.000 baris + uji waktu query

* Lokasi: `docs/smoke-test/smoke-test3/`.
* Hasil: import **0,9 dtk** (ambang 600 dtk); query agregat 50 mdetik,
  top-path brute-force 3 mdetik, drill-down 0 mdetik, hitung 401/403 6 mdetik
  (ambang 3.000 mdetik).
* Status: **LULUS** — skala 1 juta baris/bulan (±10x) diproyeksikan tetap aman
  untuk ledger evaluasi/benchmark di SQLite laptop dengan batch 5.000 + indeks
  pola. SQLite bukan pengganti Wazuh Indexer pada arsitektur v2.

## ST4 — Rule dan correlation Wazuh untuk log OJS

* Lokasi: `docs/smoke-test/smoke-test4/`.
* Isi: `local_rules.xml` (rule 100100–100131), `ossec-agent-snippet.conf`,
  `generate_sample_log.py`, `preflight_st4.py`, `sample-ojs.log` (41 baris),
  `expected-results.csv`, `run-st4.sh`, `restore-st4.sh`, `README.md`.
* Validasi statis: XML **OK**, `bash -n` **OK**, `py_compile` **OK**.
* Preflight: **ST4 PREFLIGHT PASS; rules=11; lines=41**; event counts
  100100=11, 100101=10, 100110=3, 100111=1, 100112=20, 100120=1, 100121=1;
  jendela korelasi 100102/100113/100130 terpenuhi.
* Cakupan: brute-force login, traversal, importexport/XXE, scanner 404,
  SQLi, XSS, repeated traversal/importexport.
* Status: **LULUS PREFLIGHT, BELUM DIJALANKAN PADA WAZUH** karena Wazuh
  Manager tidak tersedia di Windows. Eksekusi harus di VM Ubuntu 22.04/24.04.
* Catatan: correlation rule dapat tidak muncul pada sesi `wazuh-logtest`
  tunggal; verifikasi akhir memakai replay via agent dan `alerts.json`.
  Potensi bentrok dengan default rules Wazuh (mis. 31101/31103/31105) perlu
  dicek saat runtime.

## ST5 — MCP read-only ke Wazuh

* Lokasi: `docs/smoke-test/smoke-test5/`.
* Isi: `wazuh_readonly.py`, `test_st5.py`, `fixtures/alerts.json`,
  `requirements-st5.txt`, `run-st5.sh`, `README.md`.
* Hasil mock/fixture:
  **ST5 PASS; tools_checked=8; audit_events=9; write_tools=0**.
* Terbukti: 8 tool read-only terdaftar, tidak ada tool tulis/active response,
  output tidak memuat IP mentah, audit hanya menyimpan hash argumen,
  `from_env` menangani fixture list maupun respons Wazuh.
* Status: **LULUS pada mode mock**. Uji ke Wazuh Indexer nyata dan MCP SDK
  (`mcp>=1.27,<2`) masih menunggu VM.
* Batasan: query nyata masih mengambil alert lalu memfilter di MCP; untuk data
  besar filter harus didorong ke query DSL.

## ST6 — AI Agent summarizer dan evaluasi ringkasan

* Lokasi: `docs/smoke-test/smoke-test6/`.
* Isi: `summarizer.py`, `prompt.md`, `evaluate_st6.py`, `test_st6.py`,
  `rubric.json`, `fixtures/alerts_input.json`, `hasil-st6.json`,
  `run-st6.sh`, `README.md`.
* Hasil mode template:
  **ST6 PASS; faithfulness=5; completeness=5; actionability=5; clarity=5;
  conciseness=5**.
* Terbukti: skema output lengkap, `alert_ids` hanya dari input, CVE terikat
  data, tidak ada IP mentah, tidak ada saran pemblokiran otomatis,
  ringkasan deterministik.
* Status: **LULUS pada mode template**. Mode LLM belum diuji karena belum ada
  endpoint/API key; fallback template sudah disiapkan bila LLM gagal.
* Batasan: skor heuristic bukan pengganti rubric manusia; uji utama memakai
  dataset uji 80% dan minimal dua penilai.

## Artefak proposal

* Markdown: `docs/draf-proposal-bab1-3-v2.md`.
* DOCX: `docs/Draf-Proposal-BabI-III-v2.docx` (pandoc 3.12.1, gaya dari
  DOCX lama, tabel `TableGrid`, font Times New Roman 12, spasi 1,5).
* Build ulang: `python docs/build-docx-v2.py`.
* Abstrak 200 kata, 3 paragraf; 9 tabel; 6 page break; cover dan halaman
  identitas sudah ditambahkan; metadata judul sudah diset.
* Judul final sudah dikunci. Yang masih harus diisi: nama, NIM, telepon,
  alamat, IP semester 1–6, nama instansi mitra, dan target bulan/tahun.

## Keputusan go/no-go

**GO BERSYARAT.** Logika parser, MCP read-only, audit/redaksi, dan summarizer
sudah terbukti pada data sintetis. Tiga verifikasi wajib sebelum pengumpulan
data: (1) dapatkan izin tertulis dan akses read-only ke instalasi OJS 3.x
produksi; (2) jalankan ST4 pada Wazuh 4.14 di VM Ubuntu dan rekam
`alerts.json`; (3) jalankan ST5/ST6 dengan Wazuh Indexer nyata dan endpoint LLM
yang disetujui.

Matriks mitigasi bila asumsi gagal: parser multi-format toleran + mode
`ignore_invalid`; dashboard tetap jalan mandiri bila MCP bermasalah; agregat
harian + sampel 100rb bila log membengkak; dataset sintetis penuh bila akses
log telat; pola generik web bila pola OJS-spesifik minim di sampel; fallback
template bila LLM tidak tersedia.
