# ST5 — MCP read-only ke Wazuh

Status: **lulus pada mode mock/fixture** di lingkungan Windows.
Eksekusi terhadap Wazuh Indexer nyata dilakukan di VM Ubuntu.

## Tujuan

Membuktikan bahwa MCP server:

1. Hanya mengekspos 8 tool read-only.
2. Tidak memiliki tool tulis, active response, atau perubahan rules.
3. Mengambil alert dari Wazuh Indexer API dan mengembalikan data teredaksi.
4. Mencatat audit hash argumen tanpa menyimpan argumen mentah.
5. Tidak membocorkan IP mentah pada output.

## Isi paket

| File | Fungsi |
|---|---|
| `wazuh_readonly.py` | Core client + MCP wrapper (FastMCP) |
| `test_st5.py` | Uji 8 tool pada fixture, audit, dan redaksi IP |
| `fixtures/alerts.json` | Fixture alert Wazuh untuk mode mock |
| `requirements-st5.txt` | Dependensi MCP |
| `run-st5.sh` | Menjalankan uji ST5 |

## Uji cepat (mock, tanpa Wazuh)

```bash
cd docs/smoke-test/smoke-test5
python3 test_st5.py
```

Hasil yang diharapkan:

```text
ST5 PASS
tools_checked=8 audit_events=9 write_tools=0
```

## Uji terhadap Wazuh nyata

Pasang dependensi MCP:

```bash
python3 -m pip install -r requirements-st5.txt
```

Set environment:

```bash
export WAZUH_INDEXER_URL="https://localhost:9200"
export WAZUH_INDEXER_USER="readonly-user"
export WAZUH_INDEXER_PASSWORD="ganti-password"
export WAZUH_VERIFY_TLS="0"
export OJS_PSEUDONYM_SALT="ganti-salt-acak"
```

Jalankan MCP server:

```bash
python3 wazuh_readonly.py
```

Catatan:

- `WAZUH_VERIFY_TLS=0` hanya untuk sertifikat self-signed di laboratorium.
  Jangan dipakai di produksi.
- User indexer harus memiliki akses baca ke `wazuh-alerts-*` saja.
- Kredensial tidak boleh disimpan di repository.
- MCP memakai transport stdio; OpenCode/Claude Desktop dapat menjadi host.

## Delapan tool

| Tool | Fungsi |
|---|---|
| `rekap_harian` | Rekap alert per tanggal, rule, severity |
| `top_ip_mencurigakan` | Top sumber alert dalam hash + prefiks `/24` |
| `cari_pola_serangan` | Cari alert berdasarkan pola/rule group/URL |
| `telusur_ip` | Timeline alert untuk satu IP, output dimasking |
| `korelasi_cve_ojs` | Petakan alert ke CVE/rule group |
| `detail_alert` | Detail satu alert, bukti teredaksi |
| `statistik_rule` | Jumlah alert per rule dan level |
| `export_laporan` | Laporan JSON teredaksi, tidak menulis file |

`jelaskan_insiden` dan `saran_mitigasi` tidak ada di MCP karena keduanya
kemampuan AI Agent, bukan query data.

## Audit dan privasi

- Audit menyimpan `tool`, `args_hash` (SHA256), dan `arg_keys`.
- Nilai argumen mentah tidak disimpan.
- IP mentah diganti `srcip_hash` (16 karakter) dan `srcip_prefix` (`/24`).
- `full_log` dihapus dari output karena dapat memuat IP mentah.
- Salt pseudonim diambil dari `OJS_PSEUDONYM_SALT`.

## Batasan

- Uji mock membuktikan logika tool, bukan konektivitas Wazuh nyata.
- Query nyata masih mengambil alert lalu memfilter di sisi MCP. Untuk data
  besar, filter harus didorong ke query DSL Wazuh Indexer.
- ST5 belum menguji autentikasi JWT Wazuh Server API; metadata rule/agent
  dapat ditambahkan pada iterasi berikutnya.
