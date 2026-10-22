"""Server ST2b: tool rekap_harian yang sama, dijalankan via transport stdio.

Dipakai oleh st2b_roundtrip.py (client) untuk membuktikan dispatch
tools/call -> fungsi Python lewat protokol JSON-RPC, bukan pemanggilan langsung.
"""
import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ojs-secops-smoke")
con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE agregat(tanggal TEXT, pola TEXT, jumlah INTEGER, ip_unik INTEGER)")
SAMPLE = [("2026-10-07", "benign", 31000, 900), ("2026-10-07", "scanner", 1200, 40),
          ("2026-10-07", "bruteforce_login", 412, 3), ("2026-10-07", "traversal", 25, 2),
          ("2026-10-07", "sqli", 30, 5)]
con.executemany("INSERT INTO agregat VALUES (?,?,?,?)", SAMPLE)


@mcp.tool()
def rekap_harian(tanggal: str) -> dict:
    """Rekap serangan per pola pada tanggal YYYY-MM-DD (read-only)."""
    rows = con.execute(
        "SELECT pola, jumlah, ip_unik FROM agregat WHERE tanggal=? ORDER BY jumlah DESC",
        (tanggal,),
    ).fetchall()
    total = sum(r[1] for r in rows)
    return {"tanggal": tanggal, "total": total,
            "pola": [{"pola": r[0], "jumlah": r[1], "ip_unik": r[2]} for r in rows]}


if __name__ == "__main__":
    mcp.run()
