# Penjelasan Kode `smoke2_mcp.py` (ST2)

File: `docs/smoke-test/smoke-test2/smoke2_mcp.py`
Teknik yang diuji: **ekspos fungsi Python sebagai tool MCP teraudit**
(FastMCP, SDK resmi `mcp` 1.27.0 yang sudah terinstal).

## Tujuan uji

Menjawab sebelum judul diajukan: *“Bisakah satu fungsi Python menjadi tool
MCP yang bisa ditemukan AI dan dipanggil dengan audit tanpa data mentah?”*
Hasil: tool terdaftar, output benar (total 32.667), audit hash tercetak,
**LULUS**. Ini **validasi risiko jembatan MCP, bukan evaluasi TA** — datanya
agregat sintetis 5 baris; presisi deteksi milik ST1/Bab IV.

## Cara menjalankan

```text
python docs/smoke-test/smoke-test2/smoke2_mcp.py
```

Output yang diharapkan: `ST2 tools terdaftar: ['rekap_harian']`,
dict rekap per pola, `ST2 audit_hash: b3632841b4d7a9c8`, `ST2 RESULT: LULUS`.
Kriteria LULUS = tool muncul di `list_tools` + total agregat tepat
(31000+1200+412+25+30 = 32667).

## Peta komponen ST2

```text
[SQLite agregat: tanggal/pola/jumlah/ip_unik (hitungan, bukan IP)]
        |
        v
[@mcp.tool() rekap_harian: SELECT berparameter, read-only]
  - skema JSON diturunkan dari type hints + docstring
  - argumen AI tidak bisa jadi injeksi SQL (WHERE tanggal=?)
        |
        v
[list_tools: discovery oleh AI client]
        |
        v
[pemanggilan + assert total] --> [audit_hash SHA256 argumen] --> [LULUS]
```

## Bedah per blok kode

1. **Impor** — `asyncio` (runtime tool async MCP), `hashlib` (audit tanpa data
   mentah), `sqlite3` (agregat, bukan log mentah), `FastMCP` (SDK resmi).
   Bukti klaim “tanpa dependensi tambahan, tanpa GPU”.
2. **`FastMCP("ojs-secops-smoke")`** — nama server = identitas di
   `tools/list`; di produk final diganti nama jurnal + versi.
3. **SQLite `:memory:` + tabel `agregat` + 5 `INSERT`** — fixture uji yang
   dikunci wujudnya baris tabel (peran yang sama dengan file `.log`/`.csv`
   di ST1). Kolom `ip_unik` hanya hitungan (prinsip anonimisasi sejak
   smoke-test).
4. **`@mcp.tool()`** — inti ST2. Decorator ini (a) mendaftarkan fungsi ke
   `tools/list`, (b) menurunkan skema JSON dari type hints + docstring
   sebagai deskripsi tool untuk LLM, (c) query berparameter sehingga aman,
   (d) murni SELECT sehingga read-only terbukti dari kode.
5. **`main()`** — simulasi peran AI client: discovery → panggil →
   verifikasi total → cetak audit hash (pola audit JSONL produk final:
   simpan hash argumen, bukan nilainya; akuntabilitas tanpa PII).

## ST2b — Round-trip tools/call lewat protokol (jembatan dua arah)

File: `server_st2b.py` (server stdio: tool sama + `mcp.run()`) dan
`st2b_roundtrip.py` (client asli: `stdio_client` + `ClientSession`).
Alur yang dibuktikan: initialize/handshake → `tools/list` →
`tools/call {"name": "rekap_harian", "arguments": {"tanggal": "2026-10-07"}}`
→ dispatch ke fungsi Python → hasil kembali → assert total 32.667.
Hasil run: `ST2b RESULT: LULUS`.

Catatan implementasi (SDK 1.27): hasil fungsi dikembalikan sebagai content
teks JSON (`hasil.content[0].text`), bukan `structuredContent` — karena tool
tanpa `outputSchema` eksplisit. Client mem-`json.loads` teks tersebut.
Dengan ini sisi jembatan yang belum dibuktikan ST2 (arah MCP→Python via
transport) dinyatakan tertutup. Status ST2 keseluruhan: **LULUS penuh**.

## Temuan ST2 dan keputusan desain turunannya

Tidak ada temuan kegagalan. Keputusan desain yang dikunci: (a) semua tool
produk final mengikuti pola ini (SELECT berparameter + docstring Indonesia
sebagai deskripsi tool); (b) audit menyimpan hash argumen + hasil ringkas,
tidak pernah IP mentah. Yang TIDAK dibuktikan ST2: transport stdio live ke
OpenCode asli, autentikasi, dan multi-tool — mitigasi: dashboard tetap jalan
mandiri bila MCP bermasalah.
