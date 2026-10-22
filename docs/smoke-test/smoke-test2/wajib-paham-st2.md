# Wajib Paham ST2 (bekal seminar proposal)

## A. Empat hal yang harus bisa dijelaskan tanpa lihat catatan

1. **Anatomi `@mcp.tool()`:** decorator ini (a) mendaftarkan fungsi ke
   `tools/list` sehingga AI bisa menemukan, (b) menurunkan skema JSON dari
   *type hints* (`tanggal: str -> dict`) + docstring sebagai deskripsi tool
   untuk LLM — tanpa file skema terpisah.
2. **Read-only dibuktikan dari kode, bukan janji:** fungsi hanya berisi
   SELECT berparameter (`WHERE tanggal=?`); tidak ada INSERT/UPDATE/DELETE,
   tidak ada tool tulis yang didaftarkan. Argumen AI tidak bisa menjadi
   injeksi SQL karena parameter binding.
3. **Pola audit hash-argumen:** yang disimpan/dicetak adalah SHA256 dari
   argumen + hasil ringkas — akuntabilitas (“tool apa, kapan, argumen apa”)
   tanpa pernah menyimpan IP mentah (prinsip PII + izin stakeholder).
4. **Batas ST2:** yang dibuktikan = registrasi + skema + pola audit secara
   lokal. Transport stdio live ke OpenCode, autentikasi, dan multi-tool
   BELUM dibuktikan — mitigasi: dashboard tetap jalan mandiri bila MCP
   bermasalah; LLM hanya host yang bisa diganti (bukan objek penelitian).

## B. Jawaban satu kalimat untuk jebakan penguji

* **“Kenapa tidak REST API biasa saja?”** → Karena MCP memberi discovery
  (`list_tools`) + skema terstandar sehingga AI memakai tool tanpa kode
  integrasi khusus per client (Claude/Cursor/OpenCode sama saja).
* **“Bagaimana menjamin tool read-only?”** → Hanya SELECT yang ditulis di
  kode + query berparameter + tidak ada tool tulis terdaftar + uji tulis
  yang ditolak saat sidang sebagai bukti.
* **“Kalau AI mengirim argumen jahat bagaimana?”** → Parameter binding
  menetralkan injeksi SQL; validasi format (mis. tanggal) + timeout + batas
  ukuran output di produk final; argumen tercatat di audit untuk ditelusuri.
