# Draf Proposal Bab I–III (Kerangka — mengikuti struktur Sonya)

> Judul: **Rancang Bangun Sistem Analisis Keamanan OJS Berbasis Log
> Menggunakan MCP Server dan AI Agent dengan Metode Signature-Based Detection**
> Lokasi implementasi dan identitas: *diisi penulis*.
> Target selesai: 6 bulan.

## IDENTITAS (diisi penulis)

Nama, NIM, Program Studi TRPL, telepon, alamat, usulan judul, target selesai.

## ABSTRAK (maks 250 kata, spasi tunggal — tulis belakangan setelah Bab I–III fix)

Paragraf 1: masalah (OJS tanpa visibilitas log + CVE) + tujuan.
Paragraf 2: metode (pipeline read-only + MCP 8 tools + dashboard + evaluasi
terkontrol).
Paragraf 3: hasil yang diharapkan (presisi/recall, task-success, SUS).

## BAB I PENDAHULUAN

### 1.1 Latar Belakang

Jurnal ilmiah yang dikelola dengan Open Journal Systems (OJS) merupakan
infrastruktur publikasi yang kritis bagi perguruan tinggi: seluruh alur naskah
— pengiriman, telaah, penyuntingan, hingga publikasi — berjalan di atasnya
melalui REST API dan antarmuka web [1]. Instalasi OJS umumnya di-hosting pada
Virtualmin, yang mencatat seluruh trafik HTTP ke log Apache per domain di
`/var/log/virtualmin/` dan dapat dibaca melalui menu Logs and Reports [2].
Pada studi kasus proyek akhir ini, satu instalasi OJS menghasilkan ±1 juta
baris log per bulan (±33 ribu per hari), tetapi tidak tersedia dashboard
keamanan apa pun untuk membaca log tersebut — analis buta terhadap apa yang
terjadi di servernya sendiri.

Kebutaan itu berbahaya karena OJS terbukti menjadi target serangan nyata.
CVE-2024-56525 mendokumentasikan serangan XXE oleh peran editor jurnal yang
dapat menciptakan peran super-admin dan menyisipkan plugin backdoor melalui
unggahan dokumen XML yang direkayasa [3]. Kemudian KIS-2025-11
(CVE-2025-67890) mendokumentasikan kerentanan path traversal pada
`NativeXmlIssueGalleyFilter.php` yang memungkinkan penulisan/penimpaan berkas
sembarang di server web hingga eksekusi kode jarak jauh (RCE) [4]. Menanggapi
hal ini, PKP menerbitkan memo Oktober–Desember 2025 yang mewajibkan pembaruan
ke 3.3.0-22 / 3.4.0-10 / 3.5.0-2 [5]. Jejak upaya eksploitasi semacam itu —
probing `/api`, endpoint `importexport`, `issue_galley`, serta brute-force
halaman login — tenggelam di dalam jutaan baris log format `combined` [6]
tanpa ada yang mengangkatnya menjadi informasi.

Di sisi lain, Model Context Protocol (MCP) telah menjadi standar terbuka yang
menghubungkan AI agent dengan sistem tempat data berada melalui server yang
mengekspos tools, resources, dan prompts [7]. Satu-satunya MCP untuk OJS yang
diketahui (`ojs-mcp`) hanya menjembatani REST API editorial (naskah, telaah,
terbitan) [8] — tidak menyentuh log infrastruktur sama sekali. Sementara itu,
praktik keamanan MCP yang matang menuntut least-privilege, audit, timeout, dan
confirm-before-act untuk setiap tool [9]. Proyek akhir ini menindaklanjuti
kesenjangan tersebut dengan membangun pipeline analisis log yang read-only
(produksi tidak tersentuh), MCP server berbahasa Indonesia sebagai jembatan ke
AI agent (OpenCode), dan dashboard satu halaman sebagai pusat visibilitas.

Bahasa pemrograman yang digunakan adalah Python untuk pipeline, MCP server
(FastMCP), dan backend API (FastAPI) — dipilih karena seluruh rantai
validasi risiko (ST1–ST3) telah terbukti berjalan pada stack ini tanpa GPU
maupun server tambahan; JavaScript/Vue (+ Vite) untuk dashboard satu halaman
agar terbuka ruang upscale (misalnya multi-jurnal); dan MySQL untuk
penyimpanan empat tabel karena mendukung multi-pengguna pada tahap produksi.
Lokasi implementasi adalah instalasi OJS [NAMA INSTANSI — diisi penulis]
yang di-hosting pada Virtualmin, dengan kondisi berjalan: trafik ±1 juta
baris log per bulan, tanpa dashboard keamanan, dan akses log atas izin
tertulis stakeholder (surat dilampirkan).

### 1.2 Rumusan Masalah

Berdasarkan latar belakang di atas, rumusan masalah yang diajukan adalah
sebagai berikut:

1. Bagaimana merancang dan membangun MCP server read-only beserta dashboard
   untuk menganalisis log OJS di Virtualmin tanpa menyentuh server produksi?
2. Seberapa tepat teknik deteksi pola serangan yang diusulkan pada setiap
   pola (SQLi, XSS, traversal, XXE, brute-force login, scanner) bila diukur
   dengan presisi, recall, dan F1 pada dataset berlabel [10]?
3. Seberapa berguna AI agent yang dijembatani MCP dalam menjawab pertanyaan
   analis (task-success) dan bagaimana tingkat kegunaannya menurut analis
   (SUS)?

### 1.3 Tujuan

*Penelitian proyek akhir ini mengajukan pendekatan baru untuk analisis
keamanan OJS berbasis log dengan mempresentasikan teknik deteksi pola serangan
berbasis aturan dan skoring ambang yang diekspos sebagai MCP server read-only
berbahasa Indonesia.* Teknik ini mengombinasikan deteksi berbasis
tanda-tangan (signature-based) untuk pola yang diketahui dengan ambang laju
(rate/threshold-based) untuk perilaku agresif, mengikuti taksonomi deteksi
intrusi yang mapan [11], dengan pola generik merujuk pada aturan inti
ModSecurity [12] dan ambang brute-force merujuk pada praktik Fail2Ban yang
terbukti efektif pada pola klasik [13], [14]. Fitur unik yang ditawarkan:
(a) pola OJS-spesifik dengan korelasi CVE XXE/traversal;
(b) anonimisasi IP sejak ingest (hash + tampil /24);
(c) audit hash-argumen pada setiap tool call;
(d) generator kandidat blokir berupa teks (bukan eksekusi) serta simulasi
restore ke direktori staging. Seluruh rekayasa perangkat lunak mengikuti
prinsip perancangan dan pengujian sistem [15].

### 1.4 Manfaat

1. Bagi pengelola jurnal: visibilitas serangan harian, bukti teredaksi per
   temuan, dan saran mitigasi yang dapat ditindaklanjuti — tanpa mengubah
   apa pun di server produksi.
2. Bagi pengembangan teknologi: pola integrasi MCP read-only yang aman
   (least-privilege, audit, confirm-before-act [9]) dan dapat dipakai ulang
   untuk aplikasi PHP lain di Virtualmin.
3. Bagi penelitian selanjutnya: dataset berlabel beserta skema anotasi yang
   terdokumentasi (sesuai izin tertulis stakeholder) sebagai dasar evaluasi
   yang dapat direplikasi.

### 1.5 Batasan Masalah

1. Objek dibatasi pada log Apache format `combined` [6] dari instalasi OJS
   3.x di Virtualmin; tidak melatih atau menala-model ML/GPU dalam bentuk
   apa pun.
2. Sistem read-only terhadap produksi (bekerja dari salinan terjadwal);
   LLM eksternal hanya berperan sebagai host penjelas dan bukan objek yang
   diteliti kinerjanya (versi dan tanggal uji dicatat).
3. Tanpa pemblokiran firewall otomatis, tanpa penghapusan log, tanpa
   pembaruan OJS otomatis; aksi L1 hanya berupa generator teks dan simulasi
   restore ke staging.
4. Evaluasi ketepatan memakai 2–5 ribu baris berlabel (pilot 20% vs uji 80%);
   volume 1 juta baris hanya untuk uji throughput dan agregat.
5. Alamat IP dianonimkan; yang dipublikasikan hanya agregat dan bukti
   teredaksi, sesuai izin tertulis stakeholder.

### 1.6 Sistematika Penulisan

Proposal ini disusun dalam tiga bab. Bab I Pendahuluan memaparkan latar
belakang, rumusan masalah, tujuan, manfaat, dan batasan masalah. Bab II
Tinjauan Pustaka memaparkan penelitian terkait dan teori penunjang. Bab III
Metodologi memaparkan deskripsi solusi, desain sistem, data dan evaluasi,
serta jadwal pelaksanaan, dan ditutup dengan Daftar Pustaka.

## BAB II TINJAUAN PUSTAKA

### 2.1 Penelitian Terkait (problem sama, uniqueness berbeda)

Tabel 2.1 merangkum penelitian dan karya terkait yang paling dekat dengan
topik. Perbandingan di sini dipakai untuk menentukan ruang lingkup
penelitian, bukan untuk menyatakan bahwa analisis log maupun MCP merupakan
gagasan baru.

| Penelitian | Pendekatan/temuan | Kaitan dengan proyek akhir |
|---|---|---|
| mpasternak `ojs-mcp` (2026) | MCP untuk REST API editorial OJS 3.5/3.6 (16 read + 5 write tools) | Pembanding lapis aplikasi; proyek ini di lapis log infra, tidak tumpang tindih |
| CVE-2024-56525 (NVD/GHSA) | XXE via User XML Plugin → super-admin + backdoor (9.8) | Pola deteksi prioritas + korelasi CVE |
| KIS-2025-11 / CVE-2025-67890 | Path traversal `NativeXmlIssueGalleyFilter.php` → RCE; solusi update 3.3.0-22/3.4.0-10/3.5.0-2 | Pola deteksi prioritas + saran mitigasi |
| PKP memo Okt–Des 2025 | Imbauan update + hardening instalasi OJS | Urgensi problem domain |
| MCP security standard / RedHat 2026 | Least-privilege, audit, timeout, sandbox, confirm-before-act | Landasan desain 8 tools read-only |
| NIST SP 800-94 (Scarfone & Mell, 2007) | Taksonomi signature-based vs anomaly-based vs stateful protocol analysis | Landasan nama teknik: deteksi tanda-tangan + ambang |
| OWASP CRS (ModSecurity) | Aturan generik SQLi/XSS/LFI + skoring anomali | Acuan pola generik + skoring ambang |
| Fail2Ban + studi pembanding (CAMIC/JUMIN 2026, NSDI/USENIX) | `maxretry`/`findtime`/`bantime`; efektivitas 99,95% pola klasik vs trade-off false-positive | Acuan ambang brute-force + metrik evaluasi |

Pasternak membangun server MCP bagi REST API OJS yang terautentikasi:
model membaca naskah, telaah, terbitan, dan statistik editorial — bahkan
mengambil keputusan editorial bila write diizinkan [8]. Karya tersebut
membuktikan MCP cocok untuk OJS, tetapi seluruhnya berada di lapis aplikasi;
tidak satu pun tool menyentuh log web server. Proyek akhir ini mengisi lapis
yang kosong: log infrastruktur di bawah OJS.

Sisi kerentanan dipetakan oleh dua CVE. CVE-2024-56525 menunjukkan serangan
XXE oleh peran editor yang berujung pada peran super-admin dan plugin
backdoor melalui dokumen XML rekayasa [3]. KIS-2025-11 menunjukkan traversal
pada filter galley XML yang berujung pada penulisan berkas sembarang dan RCE,
dengan perbaikan pada rilis 3.3.0-22/3.4.0-10/3.5.0-2 [4]. Memo PKP
menegaskan urgensi pemutakhiran bagi seluruh operator OJS [5]. Ketiganya
memberi proyek ini daftar pola prioritas yang presisi, bukan sekadar pola
generik.

Sisi teknik dipetakan oleh tiga acuan. NIST SP 800-94 mendefinisikan
deteksi berbasis tanda-tangan sebagai pembandingan pola ancaman yang
diketahui terhadap kejadian teramati — sangat efektif untuk ancaman dikenal,
lemah untuk ancaman tak dikenal dan teknik evasi [11]. OWASP CRS menyediakan
aturan generik serangan web (SQLi, XSS, LFI/RFI, injeksi kode) berikut
skoring anomali bagi WAF seperti ModSecurity [12]. Praktik Fail2Ban
(`maxretry`/`findtime`/`bantime`) terbukti mencegah 99,95% brute-force
klasik pada uji 10.000 percobaan [14], dan variannya yang adaptif dengan
Random Forest menekan false-positive pola yang berkembang [13]; namun studi
produksi skala besar menunjukkan ambang statis hanya memblokir 66,1%
serangan dengan 217 false-positive, sehingga ambang harus diukur, bukan
dipercaya buta. Praktik keamanan MCP melengkapi dengan least-privilege,
audit, timeout, dan confirm-before-act [7], [9].

Celah yang ditangani: belum ada MCP untuk **keamanan OJS berbasis log** dengan
evaluasi terkontrol berbahasa Indonesia — jembatan antara deteksi pola
Teruji di atas dan analis jurnal yang buta log.

### 2.2 Teori Penunjang

#### 2.2.1 OJS, Virtualmin, dan log Apache `combined`

OJS mengekspos alur editorial melalui REST API (`/submissions`,
keputusan, berkas, publikasi, DOI) yang mensyaratkan token API dan peran
pada jurnal [1]. Di bawah aplikasi, Virtualmin mencatat trafik HTTP per
domain ke log akses dan log galat Apache yang dapat dibaca lewat menu Logs
and Reports, dengan lokasi bawaan `/var/log/virtualmin/` [2]. Format
`combined` mencatat host, identitas, pengguna, waktu, baris request
(method + path + protokol), status akhir, ukuran, referer, dan user-agent
[6]. Kolom path adalah sasaran analisis pola; kolom status (401/403/404)
adalah sinyal brute-force versus pemindaian; kolom IP dianonimkan sejak
ingest pada proyek ini.

#### 2.2.2 Deteksi pola berbasis aturan dan skoring ambang

Mengikuti taksonomi NIST [11], proyek ini memakai deteksi tanda-tangan untuk
enam pola (SQLi, XSS, traversal, XXE, brute-force login, scanner) dengan
rujukan pola generik pada CRS [12] dan pola OJS-spesifik pada CVE [3], [4].
Regex hanyalah mesin pencocoknya; tekniknya adalah pembandingan tanda-tangan
seperti pada Snort/ModSecurity/Fail2Ban. Lapisan kedua adalah ambang laju
ala Fail2Ban (`maxretry` dalam `findtime`) [13], [14] beserta skoring anomali
ala CRS [12]. Aturan dievaluasi berurutan prioritas (traversal sebelum
scanner), satu baris satu label utama, dan normalisasi/decode diterapkan
sebelum pencocokan — keputusan yang lahir dari validasi risiko ST1.
Keterbatasan yang diakui NIST berlaku di sini: buta terhadap ancaman tak
dikenal dan teknik evasi, sehingga presisi/recall diukur terbuka per pola
[10].

#### 2.2.3 MCP sebagai jembatan: host, client, server

MCP menstandarkan hubungan AI agent dengan sumber data melalui tiga peran:
host (aplikasi AI), client (konektor per server), dan server (penyedia
konteks/tools) dengan primitif tools, resources, dan prompts [7]. Server
proyek ini mengekspos 8 tools read-only berparameter melalui transport
stdio; setiap pemanggilan tercatat sebagai audit ber-hash argumen mengikuti
praktik logging dan runtime security MCP [9]. LLM berperan semata sebagai
host penjelas berbahasa Indonesia — dapat diganti tanpa mengubah evaluasi,
karena yang diukur adalah parser dan tools yang deterministik.

#### 2.2.4 Perancangan sistem web dan evaluasi

Perancangan kebutuhan, antarmuka, pengujian fungsional, dan pengelolaan
kesalahan mengikuti prinsip rekayasa perangkat lunak [15]. Backend Python
(FastAPI) melayani API JSON bagi frontend Vue (hasil build statis) serta
meng-host MCP server; Windows + MySQL + Vue + Vite menjadi stack yang
dinyatakan di Bab III. Evaluasi ketepatan memakai presisi, recall, dan F1
dengan memahami keterbatasan F-measure [10] serta akurasi
`(TP+TN)/(TP+FP+TN+FN)`; evaluasi kegunaan memakai task-success atas 20
pertanyaan analis dan SUS; evaluasi kinerja memakai throughput dan p95
latensi query.

## BAB III METODOLOGI

### 3.1 Deskripsi Solusi

Solusi yang ditawarkan menjawab rumusan masalah melalui tiga subsistem yang
terpisah tetapi terintegrasi: pipeline analisis log, MCP server, dan dashboard.
Pemisahan ini disengaja mengikuti pola jembatan Figma-MCP: aplikasi data
tetap mandiri, AI agent tetap di luar, dan MCP menjadi satu-satunya pintu
di antara keduanya [7].

Subsistem pertama adalah pipeline analisis yang bekerja read-only dari
salinan log terjadwal (produksi tidak pernah disentuh). Tahapannya: parser
toleran format `combined` [6] → normalisasi/decode → pelabelan enam pola
dengan aturan berurutan prioritas → anonimisasi IP (hash + tampil /24) →
penyimpanan ke MySQL empat tabel (`log_raw_sampel`, `agregat_harian`,
`temuan`, `audit_mcp`). Teknik deteksinya mengombinasikan tanda-tangan pola
[11], [12], [3], [4] dengan ambang laju ala Fail2Ban [13], [14]. Variabel
penelitian yang dikendalikan: versi aturan, nilai ambang, dan komposisi
dataset; variabel terikatnya: presisi/recall/F1 per pola, task-success, dan
latensi. Data primer berasal dari pengamatan log instalasi OJS studi kasus;
data sekunder berasal dari CVE dan dokumentasi resmi [3]–[5], [1], [2].

Subsistem kedua adalah MCP server Python (FastMCP) dengan 8 tools read-only
berparameter — `rekap_harian, top_ip_mencurigakan, cari_pola_serangan,
telusur_ip, korelasi_cve_ojs, jelaskan_insiden, saran_mitigasi,
export_laporan` — ditambah 2 tool L1 berupa generator teks (kandidat blokir,
simulasi restore staging). Setiap pemanggilan tercatat sebagai audit
ber-hash argumen mengikuti praktik keamanan MCP [9]. Metode pengerjaan
keseluruhan adalah prototyping (MVP L0 wajib, L1 pemanis) disertai eksperimen
komparatif terkontrol berpasangan [15].

Subsistem ketiga adalah dashboard Vue satu halaman (hasil build statis yang
disajikan FastAPI) dengan 4 panel: tren harian, distribusi pola, top IP-hash,
dan detail temuan beserta bukti teredaksi. Pemilihan Vue penuh (+ Vite)
dimaksudkan menjaga ruang upscale (misalnya multi-jurnal) atas permintaan
pembimbing, dengan mitigasi demo selalu dari hasil build, bukan dev-server.

### 3.2 Desain Sistem

Gambar 3.1 menunjukkan bagan desain sistem yang mempunyai tiga bagian.
Bagian 1 adalah jalur data (log → ingest → MySQL); Bagian 2 adalah jalur
layanan (MCP server ↔ OpenCode dan API JSON ↔ dashboard Vue); Bagian 3
adalah jalur evaluasi (dataset terkunci → matriks P1–P3 → metrik). Uraian
rinci tiap bagian mengikuti setelah gambar.

#### 3.2.1 Bagian 1 — Jalur data: ingest hingga penyimpanan

Pekerjaan dimulai dari penyalinan terjadwal harian file
`/var/log/virtualmin/*_access_log` ke direktori ingest lokal [2]. Parser
regex `combined` memecah tiap baris menjadi ip/time/method/path/status/ua
[6]; baris tak dikenal dicatat gagal dan tidak dipaksa. Normalisasi
(url-decode) diterapkan sebelum pencocokan enam aturan berurutan prioritas
(traversal sebelum scanner), satu baris satu label utama — keputusan yang
lahir dari validasi risiko ST1. IP di-hash (SHA256+salt) pada saat ingest;
label ditetapkan pada saat ingest sehingga query baca tinggal agregasi
(pemisahan jalur tulis vs baca yang dibuktikan ST1–ST3). Skema mengikuti
Gambar 3.2 (ERD 4 tabel): sampel→agregat banyak-ke-satu per tanggal×pola,
temuan merujuk sampel, audit mandiri per tool call.

#### 3.2.2 Bagian 2 — Jalur layanan: MCP server dan dashboard

MCP server mengekspos 8 tools melalui transport stdio; skema tiap tool
diturunkan dari type hints dan docstring Indonesia, query selalu
berparameter, dan tidak ada tool tulis yang didaftarkan — pola yang dibuktikan
ST2/ST2b. Backend FastAPI melayani dua hal: API JSON bagi dashboard Vue dan
file statis `dist/` hasil `npm run build` (Gambar 3.1). Use case tiap aktor
dirinci pada Tabel 3.2; alur request AI (prompt → `tools/list` →
`tools/call` → jawaban berdata) menjadi objek uji P2 pada Tabel 3.3.

#### 3.2.3 Bagian 3 — Jalur evaluasi: data, eksperimen, dan metrik

Data dan anotasi disiapkan bertahap sesuai Tabel 3.1: log sintetis 10.000
baris untuk validasi risiko; ground truth 2–5 ribu baris berlabel analis
dengan pemisahan pilot 20% vs uji 80% yang dikunci; sampel real anonim
50–100 ribu untuk validasi silang dan throughput. Matriks eksperimen
(Tabel 3.3) memakai rancangan berpasangan pada data uji yang sama: P1
(parser+aturan tanpa agent) menghasilkan label per baris; P2 (parser+MCP
agent) menjawab 20 pertanyaan analis baku; P3 membandingkan dashboard build
statis vs dev-server pada waktu muat dan keberhasilan demo offline.
Metrik dibaca sesuai Tabel 3.4: presisi/recall/F1 dan false-positive per
pola dengan ambang baca yang ditetapkan sebelum uji [10]; throughput dan
p95 latensi di MySQL; task-success 20/20; SUS dengan ambang layak ≥68.
Jadwal pelaksanaan enam bulan mengikuti Tabel 3.5, dengan ST4 (skema dan
akses MySQL berparameter) sebagai prasyarat B1 sebelum implementasi.

#### Tabel 3.1 Data dan anotasi yang disiapkan

| Komponen | Isi minimum | Fungsi |
|---|---|---|
| Log sintetis | 10.000 baris `combined` + label otomatis generator (seed tercatat) | Validasi risiko pra-judul (ST1–ST3) |
| Ground truth manual | 2–5 ribu baris dilabel analis (pola + bukti path) | Acuan presisi/recall; pisah pilot 20% vs uji 80% |
| Sampel real anonim | 50–100 ribu baris, IP di-hash + bukti teredaksi | Validasi silang + throughput |
| Agregat harian | Rekap per tanggal×pola + IP-unik (hitungan) | Sumber dashboard + tools MCP |
| Audit MCP | tool, hash argumen, hasil ringkas, latensi | Akuntabilitas + reproduksibilitas |

#### Tabel 3.2 Use case dan keluaran

| Aktor / use case | Masukan dan langkah | Keluaran |
|---|---|---|
| Analis / tanya jawab | Prompt Indonesia via OpenCode → `tools/call` | Jawaban + angka + bukti teredaksi |
| Admin / kelola | Tinjau kandidat blokir (teks) → tempel manual ke fail2ban/WAF | Aturan aktif di luar sistem (tercatat) |
| Pengembang / build frontend | `npm run build` Vue → `dist/` disajikan FastAPI | Dashboard statis siap demo |
| Penguji / evaluasi | Pilih set uji + konfigurasi terkunci → jalankan matriks | Metrik per pola + SUS |

#### Tabel 3.3 Matriks eksperimen utama (berpasangan, data uji sama)

| Kode | Perlakuan | Keluaran yang dibandingkan |
|---|---|---|
| P1 | Parser + aturan saja (tanpa agent) | Label pola per baris |
| P2 | Parser + MCP agent Bahasa Indonesia | Jawaban 20 pertanyaan analis |
| P3 | Dashboard Vue build statis vs dev-server | Waktu muat + keberhasilan demo offline |

#### Tabel 3.4 Metrik dan cara pembacaan

| Metrik | Perhitungan / interpretasi |
|---|---|
| Presisi/recall/F1 per pola | TP/FP/FN vs ground truth menurut Persamaan 3.1–3.3; ambang baca ditetapkan sebelum uji |
| False-positive | Baris benign terlabel serang; dilaporkan terbuka per pola |
| Akurasi | Menurut Persamaan 3.4 sebagai metrik pendamping |
| Throughput + p95 | Baris/detik import; p95 latensi query N ulangan di MySQL |
| Task-success | 20 pertanyaan terjawab benar + berbukti / 20 |
| SUS | Skor 5–10 analis; ambang layak ≥68 |

Ketepatan tiap pola dihitung dengan persamaan berikut. Persamaan 3.1
menyatakan presisi, yaitu proporsi temuan yang benar dari seluruh yang
dilabel serang. Persamaan 3.2 menyatakan recall, yaitu proporsi serangan
yang berhasil ditemukan dari seluruh serangan yang ada. Persamaan 3.3
menyatakan F1 sebagai rata-rata harmonik keduanya. Persamaan 3.4 menyatakan
akurasi keseluruhan sebagai metrik pendamping.

Presisi = TP / (TP + FP)                              (Persamaan 3.1)

Recall = TP / (TP + FN)                               (Persamaan 3.2)

F1 = 2 × Presisi × Recall / (Presisi + Recall)         (Persamaan 3.3)

Akurasi = (TP + TN) / (TP + FP + TN + FN)              (Persamaan 3.4)

Keterangan: TP = true positive (serangan terdeteksi benar);
FP = false positive (benign terlabel serang); TN = true negative;
FN = false negative (serangan terlewat).

#### Tabel 3.5 Rencana kerja enam bulan

| Kegiatan | B1 | B2 | B3 | B4 | B5 | B6 |
|---|---|---|---|---|---|---|
| Kajian pustaka + ST4 MySQL | █ | | | | | |
| Dataset sintetis + pelabelan | | █ | | | | |
| Pipeline + MCP 8 tools + API | | | █ | | | |
| Dashboard Vue + build statis + OpenCode | | | | █ | | |
| Kunci konfigurasi + evaluasi | | | | | █ | |
| Analisis salah + tulis + admin pengajuan | | | | | | █ |

## DAFTAR PUSTAKA (format IEEE, urut kemunculan sitasi; jurnal 5 thn terakhir, buku 10 thn)

[1] PKP, “REST API - OJS,” PKP Docs, https://docs.pkp.sfu.ca/dev/api/
(diakses Okt. 2026).
[2] Virtualmin, “How to View Website Access and Error Logs,”
https://www.virtualmin.com/docs/ (diakses Okt. 2026).
[3] National Vulnerability Database, “CVE-2024-56525,”
https://nvd.nist.gov/vuln/detail/CVE-2024-56525 (diakses Okt. 2026).
[4] E. Romano, “[KIS-2025-11] Open Journal Systems <= 3.5.0-1
(NativeXmlIssueGalleyFilter.php) Path Traversal Vulnerability,” Full
Disclosure, Des. 2025.
[5] PKP Communications, “Memo: Keeping your OJS Installation Secure,”
https://pkp.sfu.ca, Okt. 2025 (dimutakhirkan Des. 2025).
[6] Apache Software Foundation, “Log Files,” Apache HTTP Server Version 2.4
Documentation, https://httpd.apache.org/docs/2.4/logs.html (diakses Okt. 2026).
[7] Anthropic, “Model Context Protocol Specification,”
https://modelcontextprotocol.io (diakses Okt. 2026).
[8] M. Pasternak, “ojs-mcp: MCP server for the authenticated OJS REST API,”
https://github.com/mpasternak/ojs-mcp (diakses Okt. 2026).
[9] H. Sidhpurwala, “MCP security: Logging and runtime security measures,”
Red Hat Blog, Apr. 2026.
[10] D. M. W. Powers, “What the F-measure doesn’t measure: Features, Flaws,
Fallacies and Fixes,” Technical Report KIT-14-001, Flinders University, 2019.
[11] K. Scarfone and P. Mell, “Guide to Intrusion Detection and Prevention
Systems (IDPS),” NIST Special Publication 800-94, National Institute of
Standards and Technology, Gaithersburg, MD, 2007, doi:
10.6028/NIST.SP.800-94.
[12] OWASP Foundation, “OWASP ModSecurity Core Rule Set (CRS),”
https://owasp.org/projects/crs (diakses Okt. 2026).
[13] B. Sugiarto, A. Nursetyo, R. T. Subagio, Kusnadi, and P. Sokibi,
“Integration of Fail2Ban as an Artificial Intelligence Based Cyber Security
System with Random Forest Algorithm for Adaptive Detection of SSH Brute
Force Attacks,” in Proc. Cirebon Annual Multidisciplinary Int. Conf.
(CAMIC), 2026, pp. 49–53.
[14] A. Nursetyo, B. Sugiarto, Kusnadi, S. M. Saleh, and B. A. Umam,
“Pengujian Fail2Ban sebagai Mekanisme Pertahanan terhadap Serangan Brute
Force,” Jurnal Media Informatika, vol. 7, no. 1, pp. 335–343, Feb. 2026,
doi: 10.55338/jumin.v7i1.7891.
[15] R. S. Pressman and B. R. Maxim, Software Engineering: A Practitioner’s
Approach, 9th ed. New York, NY: McGraw-Hill Education, 2019.
