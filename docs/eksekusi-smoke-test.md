# Dokumentasi Eksekusi Smoke-Test (Validasi Risiko Pra-Pengajuan)

Judul: **Rancang Bangun Sistem Analisis Keamanan OJS Berbasis Log
Menggunakan MCP Server dan AI Agent dengan Metode Signature-Based Detection**

Tanggal eksekusi: 7 Oktober 2026
Lingkungan: Windows, Python 3.13.7, `mcp` SDK 1.27.0 (sudah terinstal),
tanpa instalasi tambahan, tanpa GPU, tanpa akses log produksi.
Skrip uji: `C:\Users\AMD\AppData\Local\Temp\opencode\smoke{1,2,3}_*.py`
(dataset 100% sintetis).

## ST1 — Parser format `combined` + deteksi 6 pola (1.000 baris)

* Perintah: `python smoke1_parser.py`
* Hasil: parse **1000/1000 OK, gagal 0, waktu 0,01 dtk**.
* Deteksi vs ekspektasi: sqli 42/42, xss 45/45, xxe 38/38,
  bruteforce_login 39/39 tepat; traversal 85 vs 41 dan scanner 43 vs 87 karena
  pola `../` cocok di kedua aturan (artefak data sintetis, bukan kegagalan parser).
* Keputusan desain yang dicatat: aturan evaluasi **berurutan prioritas**
  (traversal sebelum scanner) + satu baris hanya boleh satu label utama.
* Status: **LULUS dengan catatan** (catatan sudah masuk desain).

## ST2 — Satu tool MCP `rekap_harian` via FastMCP

* Lokasi paket: `docs/smoke-test/smoke-test2/` (`smoke2_mcp.py` +
  `penjelasan-smoke2.md` + `wajib-paham-st2.md`).
* Perintah: `python docs/smoke-test/smoke-test2/smoke2_mcp.py`
* Hasil: tool terdaftar (`list_tools` mengembalikan `rekap_harian`),
  output agregat benar (total 32.667), audit hash argumen tercetak,
  tidak ada IP mentah tersimpan.
* Status: **LULUS**.
* ST2b round-trip (`server_st2b.py` + `st2b_roundtrip.py`): initialize →
  `tools/list` → `tools/call rekap_harian` via stdio → total 32.667.
  Status: **LULUS** — jembatan dua arah terbukti (detail:
  `smoke-test2/penjelasan-smoke2.md` § ST2b).

## ST3 — Import 100.000 baris + uji waktu query

* Lokasi paket: `docs/smoke-test/smoke-test3/` (`smoke3_perf.py` +
  `penjelasan-smoke3.md` + `wajib-paham-st3.md`).
* Perintah: `python docs/smoke-test/smoke-test3/smoke3_perf.py`
* Hasil: import **0,9 dtk** (ambang 600 dtk); query agregat 50 mdetik,
  top-path brute-force 3 mdetik, drill-down 0 mdetik, hitung 401/403 6 mdetik
  (ambang 3.000 mdetik).
* Status: **LULUS** — skala 1 juta baris/bulan (±10x) diproyeksikan tetap aman
  di SQLite laptop dengan batch 5.000 + indeks pola.

## Keputusan go/no-go

**GO.** Seluruh dependensi inti terbukti ada (Python stdlib `ipaddress` +
`sqlite3`, `mcp.server.fastmcp`). Matriks mitigasi bila asumsi gagal di
lapangan: parser multi-format toleran + mode `ignore_invalid`; dashboard tetap
jalan mandiri bila MCP bermasalah; agregat harian + sampel 100rb bila log
membengkak; dataset sintetis penuh bila akses log telat; pola generik web bila
pola OJS-spesifik minim di sampel.
