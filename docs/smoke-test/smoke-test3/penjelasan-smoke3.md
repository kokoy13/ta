# Penjelasan Kode `smoke3_perf.py` (ST3)

File: `docs/smoke-test/smoke-test3/smoke3_perf.py`
(pindahan dari `docs/smoke-test/smoke3_perf.py`; tidak ada dua versi.)
Teknik yang diuji: **ingest batch + indeks + agregat pra-hitung** — jawaban
atas pertanyaan skala “apakah 1 juta log/bulan muat di laptop?”

## Tujuan uji

Validasi risiko SKALA (bukan ketepatan — itu milik ST1/Bab IV): 100.000 baris
sintetis di-parse, dilabel, dimasukkan SQLite, lalu 4 query analis
representatif diukur waktunya. Hasil run: import **0,9 dtk** (ambang 600),
query **0–50 mdetik** (ambang 3.000) → **LULUS** dengan margin 60–10.000×.

## Cara menjalankan

```text
python docs/smoke-test/smoke-test3/smoke3_perf.py
```

Output yang diharapkan: `ST3 import 100rb: 0,9s, total tersimpan=100000`,
4 baris waktu query dalam mdetik, dan `ST3 RESULT: LULUS`.
Kriteria LULUS = import <600 dtk + semua query <3 dtk (ambang longgar
sengaja — validasi risiko, bukan benchmark).

## Peta komponen ST3

```text
[Generator sintetis: seed=7, 15% serangan, 85% benign]
        |
        v
[Ingest: parse + label + hash-IP, batch 5.000, 1 commit]
        |
        v
[SQLite log_raw + INDEX idx_pola]
        |
        v
[4 query analis + timer dinding-waktu] --> [LULUS/GAGAL]
```

## Bedah per blok kode

1. **Mesin sama dengan ST1 (disengaja)** — regex `COMBINED` + 6 `RULES`
   identik, berbentuk list berurutan (= cermin keputusan prioritas ST1).
   `seed(7)` beda dari ST1 agar distribusi independen; 15% serangan (vs 30%
   di ST1) agar mirip trafik nyata yang mayoritas benign.
2. **Skema + indeks** — tabel `log_raw(ts, ip_hash, method, path, status,
   pola)` + `CREATE INDEX idx_pola`. Indeks inilah jawaban “kenapa cepat”:
   tanpa indeks, `GROUP BY pola` memindai penuh. Produk final menambah
   indeks `ip_hash`/`ts` + 3 tabel lain (agregat, temuan, audit).
3. **Ingest batch** — tiga keputusan produksi dalam satu baris append:
   (a) IP di-hash SAAT ingest (anonimisasi sejak pintu masuk);
   (b) label ditetapkan saat ingest sehingga query baca tinggal agregasi
   (pemisahan jalur tulis ST1 vs baca ST2);
   (c) batch 5.000 + satu `commit` (puluhan kali lebih cepat dari commit
   per baris).
4. **4 query + `timed()`** — masing-masing cermin 1 kebutuhan final:
   agregat per pola (= `rekap_harian`), top-path brute-force (= `telusur_ip`),
   drill-down 20 baris (= bukti dashboard), hitung 401/403 (= sinyal).
   `timed()` = cikal-bakal metrik “p95” Bab IV (di sana diulang N kali).
5. **Kriteria** — import <600 dtk, query <3 dtk; yang penting marginnya besar.

## Temuan ST3 dan keputusan desain turunannya

Tidak ada kegagalan. Keputusan desain yang dikunci: (a) ingest batch +
hash-saat-ingest + label-saat-ingest; (b) indeks minimal `pola`
(di produk final + `ip_hash`/`ts`); (c) agregat harian pra-hitung agar
dashboard/MCP tidak pernah memindai mentah. Yang TIDAK dibuktikan:
DB `:memory:` (final pakai file — angka naik tapi margin menutupi, Bab IV
ukur ulang), distribusi seragam (log real miring), sekali jalan (p95
statistik di Bab IV).
