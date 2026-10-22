# ST4 — Wazuh decoder, rules perilaku, dan korelasi OJS

Status: **lulus preflight statis; siap dieksekusi di VM Ubuntu; belum dijalankan
pada Wazuh nyata.**

## Tujuan

Membuktikan bahwa:

1. Log Apache `combined` dari OJS dapat didekode oleh Wazuh.
2. Rules perilaku OJS menghasilkan alert event-level yang benar.
3. Korelasi `frequency` + `timeframe` + `same_source_ip` menghasilkan alert
   insiden untuk brute-force, scanner, dan probing berulang.

ST4 dibagi menjadi dua bagian:

- **ST4a (event-level):** `wazuh-logtest` untuk decoder + rules sinyal.
- **ST4b (correlation):** sesi `wazuh-logtest` yang sama atau replay melalui
  Wazuh Agent untuk menguji rules `frequency`.

## Prasyarat

- Ubuntu 22.04/24.04.
- Wazuh Manager 4.14.x terpasang dan berjalan.
- Akses `sudo`.
- `wazuh-logtest` tersedia di `/var/ossec/bin/wazuh-logtest`.
- VM disarankan 4 vCPU, 8 GB RAM, 80 GB disk.

## Isi paket

| File | Fungsi |
|---|---|
| `local_rules.xml` | Rules perilaku OJS (ID 100100–100131) |
| `generate_sample_log.py` | Generator log sintetis + expected results |
| `preflight_st4.py` | Cek statis XML, sampel, pola rule, dan jendela korelasi |
| `sample-ojs.log` | 41 baris log Apache `combined` |
| `expected-results.csv` | Ekspektasi rule per baris |
| `ossec-agent-snippet.conf` | Contoh `localfile` untuk agent OJS |
| `run-st4.sh` | Backup, pasang rules, restart, jalankan logtest |
| `restore-st4.sh` | Kembalikan `local_rules.xml` dari backup |

## Decoder

ST4 memakai decoder `web-accesslog` bawaan Wazuh. Decoder ini sudah
mengekstrak `srcip`, `protocol`, `url`, dan `id` (status HTTP) dari format
Apache `combined`. Custom decoder OJS tidak diwajibkan untuk format ini.
Jika log OJS memiliki field tambahan, tambahkan child decoder di
`/var/ossec/etc/decoders/local_decoder.xml` setelah memverifikasi output
`wazuh-logtest`.

## Langkah eksekusi

```bash
cd docs/smoke-test/smoke-test4
python3 generate_sample_log.py
python3 preflight_st4.py
sudo bash run-st4.sh
```

Hasil preflight yang diharapkan:

```text
ST4 PREFLIGHT PASS
rules=11 lines=41 event_counts={'100100': 11, '100101': 10, '100110': 3, '100111': 1, '100112': 20, '100120': 1, '100121': 1}
correlation=100102,100113,100130; 100131=not-triggered
```

`run-st4.sh` akan:

1. Mencadangkan `local_rules.xml` ke `local_rules.xml.st4.bak`.
2. Menyalin `local_rules.xml` ke `/var/ossec/etc/rules/local_rules.xml`.
3. Me-restart `wazuh-manager`.
4. Menjalankan `wazuh-logtest` dengan seluruh isi `sample-ojs.log`.
5. Menyimpan output ke `hasil-st4.txt` dan mencetak ringkasan.

Setelah selesai:

```bash
sudo bash restore-st4.sh
```

## Ekspektasi hasil

| Skenario | Rule yang diharapkan | Catatan |
|---|---|---|
| Login gagal | `100101` | Event-level |
| Brute-force 10×/60 detik | `100102` | Korelasi; butuh state sesi |
| Traversal | `100110` | Event-level |
| Traversal berulang | `100130` | Korelasi; butuh state sesi |
| `importexport`/galley probe | `100111` | Event-level |
| SQLi | `100120` | Event-level |
| XSS | `100121` | Event-level |
| Scanner 20×404/60 detik | `100113` | Korelasi; butuh state sesi |

`expected-results.csv` memuat ekspektasi per baris.

## Jika korelasi tidak muncul di logtest

`wazuh-logtest` memakai sesi yang menyimpan histori event. Pada sebagian
versi, perilaku sesi saat input dipipe dapat berbeda. Jika rule `100102`,
`100113`, atau `100130` tidak muncul:

1. Jalankan `wazuh-logtest` interaktif, lalu tempel baris sample satu per satu.
2. Atau replay melalui Wazuh Agent:
   - salin `sample-ojs.log` ke `/var/log/ojs-smoke/ojs-access.log`;
   - tambahkan `localfile` pada agent (lihat `ossec-agent-snippet.conf`);
   - restart agent;
   - periksa `/var/ossec/logs/alerts/alerts.json` untuk rule ID terkait.

Ini bukan kegagalan rules; ini perbedaan cara pengujian state korelasi.

## Troubleshooting

- **Tidak ada alert sama sekali:** cek decoder di output `wazuh-logtest`
  (Phase 2). Pastikan `srcip`, `url`, dan `id` terisi.
- **Rule 31103/31105 yang muncul, bukan 100120/100121:** default ruleset
  menang lebih dulu. Ubah `if_sid` mengikuti rule default yang cocok, atau
  naikkan spesifisitas rule lokal.
- **Rule 100102 tidak muncul:** pastikan 10 baris login gagal berasal dari
  `srcip` yang sama dan berada dalam 60 detik.
- **Rule 100113 tidak muncul:** pastikan 20 baris 404 berasal dari `srcip`
  yang sama dan berada dalam 60 detik.
- **Rules gagal dimuat:** periksa `/var/ossec/logs/ossec.log` dan jalankan
  `wazuh-logtest` untuk melihat error XML.

## Batasan

- Sampel 100% sintetis dan tidak mewakili seluruh variasi trafik OJS.
- `preflight_st4.py` hanya memeriksa pola statis, bukan perilaku Wazuh nyata.
- Ambang 10/60 dan 20/60 adalah nilai awal, bukan nilai final evaluasi.
- ST4 tidak membuktikan kualitas deteksi pada data nyata; itu tugas evaluasi
  M0–M3.
- Jangan menjalankan ST4 di server produksi tanpa persetujuan dan backup.
