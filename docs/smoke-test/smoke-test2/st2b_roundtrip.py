"""ST2b round-trip: buktikan dispatch tools/call -> fungsi Python lewat protokol.

Client MCP asli (ClientSession + stdio) memanggil server_st2b.py:
  initialize/handshake -> tools/list -> tools/call rekap_harian -> assert hasil.
Ini menutup sisi jembatan yang belum dibuktikan ST2 (arah MCP -> Python).
"""
import asyncio
import json
import sys
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

SERVER = Path(__file__).resolve().parent / "server_st2b.py"


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    async with stdio_client(params) as (baca, tulis):
        async with ClientSession(baca, tulis) as sesi:
            await sesi.initialize()
            daftar = await sesi.list_tools()
            nama = [t.name for t in daftar.tools]
            print("ST2b tools via protokol:", nama)
            assert "rekap_harian" in nama, "tool tidak ditemukan via protokol!"
            hasil = await sesi.call_tool("rekap_harian", {"tanggal": "2026-10-07"})
            # SDK 1.27: hasil Fungsi dikembalikan sebagai content teks JSON
            # (structuredContent None bila tool tanpa outputSchema eksplisit).
            data = json.loads(hasil.content[0].text)
            print("ST2b output via protokol: total =", data["total"])
            assert data["total"] == 32667, data
            assert data["tanggal"] == "2026-10-07", data
            print("ST2b RESULT: LULUS")


asyncio.run(main())
