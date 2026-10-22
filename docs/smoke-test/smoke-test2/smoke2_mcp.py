"""Smoke-test 2: 1 tool MCP rekap_harian via FastMCP (tanpa file, tanpa jaringan).

Posisi ST2 dalam arsitektur: ST1 = jalur TULIS (pipeline: log -> label pola ->
DB). ST2 = jalur BACA (serving): AI tidak pernah menyentuh log mentah dan tidak
me-label apa pun; ia hanya memanggil tool yang membaca TABEL JADI. Kalimat
seminar: "AI tidak mendeteksi; AI menanyakan hasil deteksi."
rekap_harian adalah tool produksi betulan SEKALIGUS bukti konektivitas MCP
terkecil yang bisa diuji.
"""
# asyncio = runtime tool async MCP; hashlib = audit tanpa data mentah;
# sqlite3 = agregat (bukan log mentah); FastMCP = SDK resmi mcp 1.27.0.
import asyncio, hashlib, sqlite3
from mcp.server.fastmcp import FastMCP

# Nama server = identitas di tools/list; di produk final diganti nama jurnal + versi.
mcp = FastMCP("ojs-secops-smoke")
# SQLite :memory: di sini memerankan "file data terkunci" ST1: fixture uji yang
# dikunci wujudnya baris tabel (bukan file .log/.csv). Kolom ip_unik hanya
# HITUNGAN, bukan daftar IP (prinsip anonimisasi sejak smoke-test).
con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE agregat(tanggal TEXT, pola TEXT, jumlah INTEGER, ip_unik INTEGER)")

SAMPLE = [("2026-10-07", "benign", 31000, 900), ("2026-10-07", "scanner", 1200, 40),
          ("2026-10-07", "bruteforce_login", 412, 3), ("2026-10-07", "traversal", 25, 2),
          ("2026-10-07", "sqli", 30, 5)]
con.executemany("INSERT INTO agregat VALUES (?,?,?,?)", SAMPLE)

@mcp.tool()
def rekap_harian(tanggal: str) -> dict:
    # Decorator ini yang: (a) mendaftarkan fungsi ke tools/list,
    # (b) menurunkan skema JSON dari type hints (tanggal: str -> dict) +
    # docstring sebagai deskripsi tool untuk LLM,
    # (c) query BERPARAMETER (WHERE tanggal=?) sehingga argumen AI tidak bisa
    # menjadi injeksi SQL, (d) murni SELECT = bukti read-only.
    """Rekap serangan per pola pada tanggal YYYY-MM-DD (read-only)."""
    rows = con.execute("SELECT pola, jumlah, ip_unik FROM agregat WHERE tanggal=? ORDER BY jumlah DESC", (tanggal,)).fetchall()
    total = sum(r[1] for r in rows)
    return {"tanggal": tanggal, "total": total,
            "pola": [{"pola": r[0], "jumlah": r[1], "ip_unik": r[2]} for r in rows]}

async def main():
    # Simulasi peran AI client: discovery (list_tools) -> panggil -> verifikasi.
    tools = await mcp.list_tools()
    names = [t.name for t in tools]
    print("ST2 tools terdaftar:", names)
    assert "rekap_harian" in names, "tool tidak terdaftar!"
    out = rekap_harian("2026-10-07")
    print("ST2 output:", out)
    assert out["total"] == 32667, out  # 31000+1200+412+25+30
    # Pola audit JSONL produk final: simpan HASH argumen, bukan nilainya
    # (akuntabilitas tanpa PII). Di sini dicetak sebagai bukti pola.
    print("ST2 audit_hash:", hashlib.sha256(b"rekap_harian:2026-10-07").hexdigest()[:16])
    print("ST2 RESULT: LULUS")

asyncio.run(main())
# BATAS ST2 (seminar): yang dibuktikan = registrasi + skema + pola audit.
# Yang TIDAK dibuktikan: transport stdio live ke OpenCode asli, autentikasi,
# dan multi-tool. Mitigasi: dashboard tetap jalan mandiri bila MCP bermasalah.
