# Wajib Paham ST1 (bekal seminar proposal)

## A. Empat hal yang harus bisa dijelaskan tanpa lihat catatan

1. **Nama tekniknya: signature-based + threshold-based** (NIST SP 800-94
   §2.3). Regex hanya mesin pencocoknya — sama seperti yang dipakai
   Snort/ModSecurity/Fail2Ban, hanya scope saya log Apache OJS.
2. **Beda tiga kata: deteksi vs blokir vs pulih.** Deteksi (melihat pola di
   log) otomatis dan aman; blokir/pencegahan (menolak IP) butuh wewenang
   operasi — di TA ini hanya berupa *daftar kandidat + snippet teks* yang
   ditempel admin manual; pemulihan (restore file) butuh backup — di TA ini
   hanya simulasi ke direktori staging.
3. **Klaim akurasi yang benar: upaya, bukan vonis.** Tanda-tangan CVE yang
   diketahui (XXE `<!ENTITY`, traversal `../` di galley) membuat deteksi
   *upaya* eksploitasi sangat akurat; access log tidak bisa membuktikan
   “server jebol” — itu butuh korelasi lanjutan di luar scope MVP.
4. **Dua kelemahan + mitigasi:** (a) evasion encoding → normalisasi/decode
   sebelum pencocokan; (b) false-positive kata benign → korelasi status code
   + ambang agregat per IP + verifikasi manusia; keduanya dilaporkan terbuka
   di Bab IV via presisi/recall.

## B. Jawaban satu kalimat untuk jebakan penguji

* **“Kenapa tidak pakai ML saja?”** → Karena pola tanda-tangan deterministik,
  murah (0,01 dtk/1000 baris, tanpa GPU), dan hasilnya exact sehingga bisa
  dievaluasi, sedangkan ML butuh data latih + GPU + biaya server.
* **“Kenapa AI tidak auto-blokir saja?”** → Karena ambang yang galak menaikkan
  false-positive (data NSDI: FP Fail2Ban 217→1051) dan blokir butuh wewenang
  operasi; yang dinilai TA ini ketepatan daftar kandidatnya, bukan jumlah IP
  yang dieksekusi.
* **“Data sintetis sah untuk TA?”** → Sah hanya sebagai validasi risiko
  pra-judul; seluruh metrik Bab IV diukur pada dataset berlabel terpisah
  (pilot 20% vs uji 80% + validasi silang sampel real anonim).
