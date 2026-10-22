# Wajib Paham ST3 (bekal seminar proposal)

## A. Empat hal yang harus bisa dijelaskan tanpa lihat catatan

1. **Indeks adalah jawaban kecepatan:** `CREATE INDEX idx_pola` membuat
   `GROUP BY pola` tidak memindai penuh — tanpa indeks, query agregat atas
   100rb baris melambat drastis. Produk final menambah indeks `ip_hash`/`ts`.
2. **Tiga keputusan ingest:** batch 5.000 + satu commit (puluhan kali lebih
   cepat), hash IP saat ingest (anonimisasi sejak pintu masuk), label saat
   ingest (query baca tinggal agregasi — pemisahan jalur tulis vs baca).
3. **Beda `:memory:` vs file:** ST3 memakai memori (tercepat); produk final
   pakai file + 4 tabel sehingga angka naik — tetapi margin 60–10.000×
   menutupinya, dan Bab IV wajib ukur ulang di DB file.
4. **Cara baca margin ambang:** ambang ST3 longgar sengaja (validasi risiko,
   bukan benchmark); yang dinilai bukan angkanya, melainkan marginnya.
   Proyeksi 1 juta/bulan ≈ 10× uji ≈ ±9 dtk import — masih di laptop.

## B. Jawaban satu kalimat untuk jebakan penguji

* **“100 ribu ≠ 1 juta?”** → Margin 60–10.000× menutupi 10× skala, dan Bab IV
  mengukur ulang throughput + p95 di DB file pada data berlabel.
* **“Kenapa tidak MySQL langsung?”** → SQLite nol-server menjamin demo
  sidang offline; migrasi <1 hari bila stakeholder mewajibkan multi-user,
  karena seluruh SQL terisolasi di satu modul berparameter.
* **“Distribusi sintetis tidak realistis?”** → Benar — log real miring
  (satu bot bisa 50% trafik); itulah alasan indeks `ip_hash`/`ts` dan
  agregat harian masuk desain, dan evaluasi presisi memakai data berlabel
  terpisah, bukan data ST3.
