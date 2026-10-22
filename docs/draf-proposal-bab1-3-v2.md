::: {custom-style="CoverTitle"}
PROPOSAL PROYEK AKHIR
:::

::: {custom-style="CoverSubtitle"}
Pengembangan dan Implementasi Security Operations Center Berbasis Log untuk Analisis Keamanan Open Journal Systems Menggunakan MCP Server dan AI Agent dengan Metode Behavior-Based Detection
:::

::: {custom-style="CoverText"}
Oleh:
:::

::: {custom-style="CoverText"}
**[NAMA MAHASISWA]**
:::

::: {custom-style="CoverText"}
NIM **[NIM]**
:::

::: {custom-style="CoverText"}
PROGRAM STUDI TEKNOLOGI REKAYASA PERANGKAT LUNAK
:::

::: {custom-style="CoverText"}
JURUSAN TEKNOLOGI INFORMASI
:::

::: {custom-style="CoverText"}
POLITEKNIK NEGERI PADANG
:::

::: {custom-style="CoverText"}
2026
:::

<!-- Catatan internal: placeholder [ ] wajib dilengkapi sebelum pengajuan. -->

## IDENTITAS MAHASISWA

- **Nama:** [Nama Lengkap]
- **NIM:** [NIM]
- **Program Studi:** Teknologi Rekayasa Perangkat Lunak
- **Nomor Telepon:** [Nomor HP]
- **Alamat:** [Alamat Lengkap]
- **IP Semester 1–6:** [IP-1], [IP-2], [IP-3], [IP-4], [IP-5], [IP-6]
- **Usulan Judul Proyek Akhir:** Pengembangan dan Implementasi Security Operations Center Berbasis Log untuk Analisis Keamanan Open Journal Systems Menggunakan MCP Server dan AI Agent dengan Metode Behavior-Based Detection
- **Lokasi Implementasi:** Instalasi OJS 3.x produksi pada [Nama Instansi Mitra]
- **Target Selesai:** 6 bulan ([bulan dan tahun])

## ABSTRAK

Open Journal Systems (OJS) menyimpan jejak aktivitas keamanan pada log Apache,
tetapi pengelola jurnal sering tidak memiliki dashboard untuk membaca jutaan
baris log tersebut. Akibatnya, upaya probing, brute-force, traversal, dan
eksploitasi CVE OJS tenggelam di antara trafik normal. Penelitian ini
merancang SOC teknis berbasis log skala terbatas yang menggunakan Wazuh sebagai
mesin deteksi, MCP server read-only sebagai jembatan, dan AI Agent summarizer.
Objek implementasi adalah instalasi OJS 3.x produksi pada instansi mitra.

Metode yang diusulkan adalah behavior-based detection dengan rule-based
correlation dan threshold analysis. Log Apache format `combined` dikumpulkan
secara read-only oleh Wazuh Agent, didekode menjadi field terstruktur, lalu
dianalisis memakai rules perilaku OJS serta korelasi `frequency`, `timeframe`,
dan `same_source_ip`. Alert diekspos melalui delapan tool MCP read-only dan
diringkas AI Agent berbahasa Indonesia. Rancangan evaluasi memakai matriks
M0–M3: default rules Wazuh, rules event-level OJS, korelasi/ambang, dan
korelasi ditambah MCP serta AI Agent. Pengukuran mencakup precision, recall,
F1, false-positive rate, alert reduction, kualitas ringkasan, task-success,
dan SUS.

Hasil yang diharapkan adalah sistem yang mampu mengubah event log menjadi
alert dan ringkasan yang dapat ditindaklanjuti, tetap read-only, tanpa
pemblokiran otomatis, serta menyediakan bukti teredaksi untuk analis. Evaluasi
deteksi dipisahkan dari evaluasi ringkasan agar kontribusi metode behavior-based
dan AI Agent dapat dinilai secara jelas.

## BAB I PENDAHULUAN

### 1.1 Latar Belakang

Jurnal ilmiah yang dikelola dengan Open Journal Systems (OJS) merupakan
infrastruktur publikasi yang kritis bagi perguruan tinggi: seluruh alur naskah
— pengiriman, telaah, penyuntingan, hingga publikasi — berjalan di atasnya
melalui REST API dan antarmuka web [1]. Instalasi OJS umumnya di-hosting pada
Virtualmin, yang mencatat seluruh trafik HTTP ke log Apache per domain di
`/var/log/virtualmin/` dan dapat dibaca melalui menu Logs and Reports [2].
Pada instalasi OJS 3.x produksi yang menjadi lokasi implementasi, trafik
mencapai ±1 juta baris log per bulan (±33 ribu per hari), tetapi tidak tersedia
dashboard keamanan untuk membaca log tersebut — analis buta terhadap apa yang
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

Persoalannya bukan sekadar ketiadaan alat, tetapi ketiadaan metode yang
menghubungkan event mentah menjadi perilaku serangan yang dapat dibaca.
Pencocokan pola tunggal seperti regex SQLi atau XSS hanya menangkap sinyal
permukaan; ia tidak melihat bahwa serangkaian permintaan dari sumber yang sama
merupakan probing, brute-force, atau eksploitasi bertahap. Di sisi lain,
analis jurnal tidak memiliki waktu untuk memeriksa ratusan ribu baris log per
hari. Di sinilah behavior-based detection diperlukan: deteksi atas perilaku
yang tampak dari frekuensi, urutan, dan kombinasi konteks event, bukan semata
pencocokan artefak yang sudah dikenal.

Wazuh 4.14 dipilih sebagai mesin deteksi karena merupakan SIEM/XDR open source
yang menyediakan agent, manager, indexer, dashboard, REST API, decoder, dan
rule engine dalam satu ekosistem [7]. Wazuh memungkinkan log Apache OJS
dikumpulkan secara read-only, didekode menjadi field terstruktur, lalu
dianalisis dengan rules XML [8]. Namun, default ruleset Wazuh sebagian besar
bersifat signature-like: ia mengenali pola yang sudah dikenal, bukan perilaku
multi-event yang khas OJS. Karena itu, proyek ini tidak berhenti pada
pemasangan Wazuh. Lapisan nilai tambahnya adalah **rules perilaku OJS,
korelasi ambang, dan child decoder OJS bila diperlukan**, yang dievaluasi
secara terkontrol.

Model Context Protocol (MCP) telah menjadi standar terbuka yang
menghubungkan AI agent dengan sistem tempat data berada melalui server yang
mengekspos tools, resources, dan prompts [9]. Satu-satunya MCP untuk OJS yang
diketahui (`ojs-mcp`) hanya menjembatani REST API editorial (naskah, telaah,
terbitan) [10] — tidak menyentuh log infrastruktur sama sekali. Sementara itu,
praktik keamanan MCP yang matang menuntut least-privilege, audit, timeout, dan
confirm-before-act untuk setiap tool [11]. Proyek akhir ini menindaklanjuti
kesenjangan tersebut dengan membangun MCP server read-only sebagai jembatan
ke AI agent, bukan sebagai mesin deteksi.

AI Agent berperan pada tahap akhir: merangkum alert Wazuh, menjelaskan
konteks, dan menyusun saran mitigasi berbahasa Indonesia. AI Agent tidak
mendeteksi dan tidak memblokir. Pemisahan ini penting agar evaluasi deteksi
(Wazuh) dan evaluasi ringkasan (AI) tidak tercampur. Dengan demikian, kontribusi
utama proyek ini adalah **metode behavior-based detection dengan rule-based
correlation dan threshold analysis untuk log OJS**, yang diimplementasikan pada
Wazuh dan diekspos melalui MCP read-only untuk diringkas AI Agent.

Secara operasional, sistem ini diposisikan sebagai **SOC teknis berbasis log
skala terbatas**. Cakupannya adalah koleksi log, deteksi, korelasi, penyajian
alert, dan akses read-only untuk peringkasan; cakupan ini tidak mencakup tim
SOC 24/7, SOAR, ticketing, case management, threat intelligence, atau IDS
jaringan. Pembatasan tersebut ditegaskan pada §1.5 agar klaim judul tidak
melebihi bukti yang diuji.

Lokasi implementasi adalah instalasi OJS 3.x produksi milik
[Nama Instansi Mitra] yang di-hosting pada Virtualmin, dengan trafik ±1 juta
baris log per bulan dan tanpa dashboard keamanan. Akses log dilakukan secara read-only dengan
izin tertulis stakeholder (surat izin dilampirkan pada proposal). Untuk menjaga
reproduksibilitas dan etika, evaluasi dilakukan pada salinan log terkontrol;
arsitektur deployment mendukung Wazuh Agent read-only pada server OJS.

### 1.2 Rumusan Masalah

Berdasarkan latar belakang di atas, rumusan masalah yang diajukan adalah
sebagai berikut:

1. Bagaimana merancang SOC teknis berbasis log skala terbatas untuk OJS dengan
   Wazuh sebagai mesin deteksi, MCP server read-only sebagai jembatan ke AI
   Agent, tanpa mengubah aplikasi OJS?
2. Seberapa baik metode behavior-based detection dengan rule-based correlation
   dan threshold analysis mendeteksi pola serangan OJS (SQLi, XSS, traversal,
   XXE, brute-force login, scanner) dibandingkan default ruleset Wazuh?
3. Seberapa baik kualitas ringkasan AI Agent dan kegunaan sistem bagi analis,
   diukur dengan rubric ringkasan, task-success, dan SUS?

### 1.3 Tujuan

1. Merancang dan membangun SOC teknis berbasis log skala terbatas untuk OJS,
   dengan Wazuh sebagai mesin deteksi, MCP server read-only, dan AI Agent
   summarizer.
2. Mengukur ketepatan metode behavior-based detection dengan rule-based
   correlation dan threshold analysis pada dataset berlabel, serta
   membandingkannya dengan default ruleset Wazuh.
3. Mengukur kualitas ringkasan AI Agent dan kegunaan sistem bagi analis.

### 1.4 Manfaat

1. **Bagi pengelola jurnal:** visibilitas alert keamanan harian, bukti
   teredaksi per temuan, dan saran mitigasi yang dapat ditindaklanjuti tanpa
   mengubah aplikasi OJS.
2. **Bagi pengembangan teknologi:** pola integrasi Wazuh + MCP read-only + AI
   summarizer yang aman (least-privilege, audit, tanpa auto-block) dan dapat
   dipakai ulang untuk aplikasi PHP lain di Virtualmin.
3. **Bagi penelitian selanjutnya:** dataset berlabel, aturan perilaku OJS, dan
   skema evaluasi ringkasan yang terdokumentasi sebagai dasar replikasi.

### 1.5 Batasan Masalah

1. Objek dibatasi pada log Apache format `combined` [6] dari instalasi OJS 3.x
   di Virtualmin; tidak melatih model ML/GPU dan tidak membangun UEBA.
2. Wazuh yang digunakan adalah versi 4.14.x pada Ubuntu 22.04/24.04; konfigurasi
   laboratorium memakai VM 4 vCPU, 8 GB RAM, dan 80 GB disk.
3. Sistem bersifat read-only terhadap OJS: Wazuh Agent hanya membaca log
   (pemasangan agent adalah layanan tambahan di server, bukan perubahan
   aplikasi OJS), MCP hanya melakukan query, dan tidak ada pemblokiran
   firewall otomatis, penghapusan log, atau pembaruan OJS otomatis.
4. AI Agent hanya berperan sebagai summarizer/penjelas; ia tidak menentukan
   label serangan dan tidak menggantikan keputusan analis. Versi model dan
   tanggal uji dicatat.
5. Evaluasi ketepatan memakai 2–5 ribu baris berlabel (pilot 20% vs uji 80%);
   volume 1 juta baris hanya untuk uji throughput dan agregat.
6. Alamat IP mentah dibatasi pada Wazuh dengan RBAC; MCP dan laporan
   menampilkan hash SHA256+salt serta prefiks `/24`. Publikasi hanya berisi
   agregat dan bukti teredaksi sesuai izin tertulis stakeholder.
7. SOC yang diimplementasikan adalah SOC teknis berbasis log skala terbatas,
   bukan SOC organisasi penuh. Penelitian tidak mencakup tim 24/7, SOAR,
   ticketing, case management, threat intelligence, maupun IDS jaringan
   seperti Suricata; Wazuh adalah satu-satunya platform deteksi.

### 1.6 Sistematika Penulisan

Proposal ini disusun dalam tiga bab. Bab I Pendahuluan memaparkan latar
belakang, rumusan masalah, tujuan, manfaat, dan batasan masalah. Bab II
Tinjauan Pustaka memaparkan penelitian terkait dan teori penunjang. Bab III
Metodologi memaparkan deskripsi solusi, desain sistem, data dan evaluasi,
serta jadwal pelaksanaan, dan ditutup dengan Daftar Pustaka.

## BAB II TINJAUAN PUSTAKA

### 2.1 Penelitian Terkait

Tabel 2.1 merangkum penelitian dan karya terkait yang paling dekat dengan
topik. Perbandingan dipakai untuk menentukan ruang lingkup penelitian, bukan
untuk menyatakan bahwa SIEM, Wazuh, MCP, atau LLM merupakan gagasan baru.

**Tabel 2.1 Penelitian dan karya terkait.**

| Penelitian/karya | Pendekatan/temuan | Kaitan dengan proyek akhir |
|---|---|---|
| Wazuh 4.14 [7], [8], [12], [13] | SIEM/XDR open source: agent, manager, indexer, dashboard, decoder, rules, correlation, REST API | Platform deteksi dan sumber alert; belum memiliki decoder/rules perilaku OJS |
| Wazuh MCP Server [14] | 41 tool read + 14 tool write untuk alert, agent, vulnerability, compliance, active response | Pembanding integrasi MCP-Wazuh; proyek ini membatasi diri pada read-only dan konteks OJS |
| `ojs-mcp` [10] | MCP untuk REST API editorial OJS (naskah, telaah, terbitan) | Pembanding lapis aplikasi; proyek ini di lapis log infrastruktur |
| CVE-2024-56525 [3] | XXE via User XML Plugin → super-admin + backdoor | Pola perilaku prioritas + korelasi CVE |
| KIS-2025-11 / CVE-2025-67890 [4] | Path traversal `NativeXmlIssueGalleyFilter.php` → RCE | Pola perilaku prioritas + saran mitigasi |
| PKP memo Okt–Des 2025 [5] | Imbauan update + hardening instalasi OJS | Urgensi problem domain |
| MCP specification [9] dan praktik keamanan MCP [11] | Host/client/server; least-privilege, audit, timeout, confirm-before-act | Landasan desain MCP read-only |
| NIST SP 800-94 [15] | Taksonomi signature-based, anomaly-based, stateful protocol analysis | Landasan konsep deteksi dan batas metode |
| OWASP CRS [16] | Aturan generik SQLi/XSS/LFI + skoring anomali | Acuan pola permukaan, bukan metode utama |
| Fail2Ban [17], [18] | `maxretry`/`findtime`/`bantime`; efektivitas dan false-positive | Acuan ambang brute-force |
| LLMs in the SOC [19] | LLM dipakai untuk sensemaking dan context-building, bukan keputusan berisiko tinggi | Landasan peran AI sebagai summarizer |
| MESSALA [20] | Evaluasi laporan SOC multi-perspektif | Acuan rubric evaluasi ringkasan |

Wazuh adalah karya yang paling dekat dari sisi platform. Ia menyediakan
decoder, rules, korelasi, indexer, dashboard, dan API yang dibutuhkan untuk
membangun alur deteksi [7], [8], [12], [13]. Namun, Wazuh bersifat generik:
tidak ada decoder OJS-spesifik, tidak ada rules perilaku untuk endpoint OJS,
dan default ruleset-nya lebih banyak berpijak pada pola yang sudah dikenal.
Proyek ini mengisi ruang tersebut dengan model perilaku OJS yang eksplisit.

Wazuh MCP Server [14] membuktikan bahwa Wazuh dapat diekspos ke LLM melalui
MCP. Karya tersebut menyediakan 55 tool, termasuk 14 tool yang mengubah state
(active response dan rollback). Proyek ini tidak bersaing pada kelengkapan
tool. Justru sebaliknya: proyek ini membatasi MCP pada 8 tool read-only yang
spesifik OJS, dengan audit hash argumen dan tanpa kemampuan menulis ke Wazuh.
Perbedaan ini penting karena konteks proyek akhir menuntut sistem yang aman
dan dapat dipertanggungjawabkan, bukan agen otonom yang memblokir IP.

`ojs-mcp` [10] menunjukkan bahwa MCP cocok untuk OJS, tetapi seluruhnya berada
di lapis aplikasi editorial; tidak satu pun tool menyentuh log web server.
Proyek ini mengisi lapis yang kosong: log infrastruktur di bawah OJS.

Sisi kerentanan dipetakan oleh dua CVE. CVE-2024-56525 menunjukkan serangan
XXE oleh peran editor yang berujung pada peran super-admin dan plugin
backdoor melalui dokumen XML rekayasa [3]. KIS-2025-11 menunjukkan traversal
pada filter galley XML yang berujung pada penulisan berkas sembarang dan RCE,
dengan perbaikan pada rilis 3.3.0-22/3.4.0-10/3.5.0-2 [4]. Memo PKP
menegaskan urgensi pemutakhiran bagi seluruh operator OJS [5]. Ketiganya
memberi proyek ini daftar perilaku prioritas yang presisi, bukan sekadar pola
generik.

Sisi metode dipetakan oleh NIST SP 800-94 [15]. NIST membedakan deteksi
berbasis tanda-tangan, berbasis anomali, dan analisis protokol stateful.
Proyek ini tidak mengklaim membangun anomaly-based detection atau ML. Yang
dibangun adalah **behavior-based detection berbasis aturan**: rules menandai
sinyal perilaku, lalu correlation dan threshold mengangkat sinyal tersebut
menjadi alert insiden. OWASP CRS [16] dan praktik Fail2Ban [17], [18] dipakai
sebagai acuan pola permukaan dan parameter ambang, bukan sebagai metode
utama.

Sisi AI dipetakan oleh studi LLM di SOC [19] dan MESSALA [20]. Studi tersebut
menunjukkan bahwa LLM lebih tepat diposisikan sebagai alat bantu sensemaking
dan context-building, bukan pengambil keputusan berisiko tinggi. MESSALA
memberi acuan bahwa kualitas laporan SOC perlu dievaluasi multi-perspektif,
tidak cukup hanya “terdengar masuk akal”. Karena itu, AI Agent dalam proyek
ini hanya merangkum output MCP dan dievaluasi dengan rubric yang eksplisit.

Celah yang ditangani: belum ada sistem **behavior-based detection log OJS**
yang diimplementasikan pada Wazuh, diekspos melalui MCP read-only, dan
dievaluasi bersama kualitas ringkasan AI Agent dalam konteks Indonesia.

### 2.2 Teori Penunjang

#### 2.2.1 Security Operations Center (SOC) Berbasis Log

SOC adalah fungsi terpusat yang memantau, mengorelasikan, dan menganalisis
peristiwa keamanan untuk mendeteksi serta menanggapi insiden. SOC yang matang
menggabungkan people, process, dan technology serta beroperasi secara
berkelanjutan. Proyek ini tidak membangun SOC organisasi penuh. Yang
diimplementasikan adalah komponen technology berupa SOC teknis berbasis log
skala terbatas.

Dalam batas tersebut, SOC dioperasionalkan sebagai pipeline: koleksi log Apache
OJS, decoding, rules perilaku, korelasi/ambang, penyimpanan alert, penyajian
dashboard, dan akses read-only melalui MCP untuk diringkas AI Agent. Unsur
people/process dibatasi pada analis yang membaca alert; tidak ada tim 24/7,
SOAR, ticketing, case management, atau threat intelligence. Pembatasan ini
penting agar klaim “SOC” pada judul tidak melebihi bukti yang diuji.

#### 2.2.2 OJS, Virtualmin, dan log Apache `combined`

OJS mengekspos alur editorial melalui REST API (`/submissions`, keputusan,
berkas, publikasi, DOI) yang mensyaratkan token API dan peran pada jurnal [1].
Di bawah aplikasi, Virtualmin mencatat trafik HTTP per domain ke log akses dan
log galat Apache yang dapat dibaca lewat menu Logs and Reports, dengan lokasi
bawaan `/var/log/virtualmin/` [2]. Format `combined` mencatat host, identitas,
pengguna, waktu, baris request (method + path + protokol), status akhir,
ukuran, referer, dan user-agent [6]. Kolom path adalah sasaran analisis pola;
kolom status (401/403/404) adalah sinyal brute-force versus pemindaian; kolom
IP dipakai untuk korelasi sumber.

#### 2.2.3 Wazuh sebagai mesin deteksi

Wazuh 4.14 terdiri atas empat komponen utama: agent, manager, indexer, dan
dashboard [7]. Agent membaca log lokal melalui konfigurasi `localfile` dan
mengirimkannya ke manager. Manager menjalankan decoder untuk memecah log
menjadi field, lalu rules untuk menentukan apakah event memenuhi kondisi
tertentu. Alert dikirim ke indexer dan ditampilkan pada dashboard; API
manager dan API indexer menyediakan akses terprogram [12], [13].

Decoder Wazuh dapat memanfaatkan decoder `web-accesslog` bawaan untuk log
Apache, lalu ditambah child decoder untuk field OJS yang lebih spesifik [8].
Rules ditulis dalam XML dan mendukung `if_sid`, `match`, `regex`, `frequency`,
`timeframe`, `same_source_ip`, serta `if_matched_sid` [8]. Kombinasi
`frequency`, `timeframe`, dan `same_source_ip` inilah yang menjadi dasar
korelasi perilaku: event yang sama atau terkait dihitung dalam jendela waktu
tertentu, dari sumber yang sama.

Default ruleset Wazuh sudah mencakup beberapa pola web generik, misalnya SQLi
dan XSS. Namun, default tersebut tidak memahami konteks OJS seperti
`importexport`, `issue_galley`, atau halaman login jurnal. Default ruleset
juga tidak mengetahui ambang yang tepat untuk trafik OJS. Karena itu, default
ruleset diposisikan sebagai baseline (M0), bukan sebagai solusi final.

#### 2.2.4 Behavior-based detection dengan rule-based correlation dan threshold

Behavior-based detection adalah pendekatan yang mendeteksi berdasarkan
perilaku yang teramati, bukan berdasarkan artefak statis semata. Perilaku di
sini dioperasionalkan menjadi tiga kelompok:

1. **Frekuensi/velocity:** jumlah event dalam jendela waktu, misalnya 10
   login gagal dalam 60 detik dari IP yang sama.
2. **Urutan/sequence sederhana:** rangkaian event yang saling terkait,
   misalnya probing `/api` diikuti akses `importexport` dan unggahan XML.
3. **Kombinasi konteks:** path + status + user-agent + waktu + sumber yang
   bersama-sama menunjukkan perilaku mencurigakan.

Perbedaan dengan signature-based dapat dilihat pada Tabel 2.2.

**Tabel 2.2 Perbandingan signature-based dan behavior-based.**

| Aspek | Signature-based | Behavior-based |
|---|---|---|
| Unit analisis | artefak/pola yang sudah dikenal | aksi/perilaku dalam konteks waktu |
| Contoh | string `union select`, pola payload XSS | 20 login gagal/60 detik dari IP sama |
| Kekuatan | ancaman dikenal, false-positive relatif rendah | variasi dan serangan multi-langkah |
| Kelemahan | mudah dihindari, buta ancaman baru | perlu tuning, rawan false-positive |
| Implementasi Wazuh | default rules/regex | custom rules + `frequency`/`timeframe`/`same_source_ip` |

Behavior-based detection **bukan** sinonim signature-based, tetapi keduanya
dapat bertumpang tindih dalam implementasi. Regex untuk SQLi tetap bersifat
signature-like; yang membuat sistem ini behavior-based adalah lapisan
korelasi dan ambang yang mengangkat sinyal tunggal menjadi insiden. Oleh
karena itu, evaluasi harus memisahkan kontribusi aturan event-level (M1) dari
kontribusi korelasi/ambang (M2).

Metode ini juga **bukan** anomaly-based detection atau UEBA. Tidak ada
baseline learning, model probabilistik, atau ML di dalamnya. Batasnya adalah
rule-based behavior: perilaku yang dapat dinyatakan sebagai kondisi XML,
frekuensi, waktu, dan kesamaan sumber. Keterbatasan ini diakui secara
terbuka: sequence arbitrer dan ancaman yang tidak memiliki sinyal aturan
tidak akan tertangkap.

#### 2.2.5 MCP sebagai jembatan read-only

MCP menstandarkan hubungan AI agent dengan sumber data melalui tiga peran:
host (aplikasi AI), client (konektor per server), dan server (penyedia
konteks/tools) dengan primitif tools, resources, dan prompts [9]. Server
proyek ini mengekspos 8 tools read-only berparameter melalui transport stdio;
setiap pemanggilan tercatat sebagai audit ber-hash argumen mengikuti praktik
keamanan MCP [11].

MCP server tidak mendeteksi dan tidak menulis. Ia hanya menerjemahkan
pertanyaan analis menjadi query ke Wazuh Indexer API (`wazuh-alerts-*`) dan
Wazuh Server API untuk metadata rule/agent [12], [13]. Dengan demikian, MCP
adalah **bridge**, bukan detection engine. AI Agent memakai bridge ini untuk
mengambil data yang sudah terstruktur, lalu menyusun ringkasan.

#### 2.2.6 AI Agent sebagai summarizer

AI Agent dalam proyek ini adalah host LLM yang terhubung ke MCP server. Ia
menerima alert terstruktur (rule, severity, srcip hash, path, status, waktu,
jumlah event) dan menghasilkan ringkasan berbahasa Indonesia. Studi LLM di
SOC menunjukkan bahwa LLM paling berguna sebagai alat bantu sensemaking dan
context-building, bukan sebagai pengambil keputusan akhir [19]. Karena itu,
AI Agent tidak menentukan label serangan dan tidak melakukan pemblokiran.

Agar dapat dievaluasi, output AI dibatasi pada skema JSON:

```json
{
  "ringkasan": "...",
  "severity": "low|medium|high|critical",
  "indikator": ["..."],
  "dampak": "...",
  "mitigasi": ["..."],
  "alert_ids": ["..."],
  "ketidakpastian": "..."
}
```

Guardrail yang dipakai: (a) hanya boleh merangkum data yang diberikan MCP;
(b) wajib menyertakan `alert_ids`; (c) tidak boleh mengarang IP, path, atau
CVE; (d) tidak boleh menyarankan tindakan otomatis; (e) harus menyatakan
ketidakpastian bila data tidak cukup. Evaluasi kualitas ringkasan mengikuti
gagasan MESSALA bahwa laporan SOC perlu dinilai dari beberapa perspektif,
bukan hanya kelancaran bahasa [20].

#### 2.2.7 Evaluasi deteksi dan kegunaan

Evaluasi deteksi memakai presisi, recall, dan F1 dengan pemahaman atas
keterbatasan F-measure [21], serta false-positive rate per pola. Karena
behavior-based detection bekerja pada level insiden, evaluasi dibagi menjadi:

- **Event-level:** satu baris log; dipakai untuk M1 (aturan event).
- **Incident-level:** grup `srcip + pola + time window`; dipakai untuk M2
  (korelasi/ambang).

Evaluasi kegunaan memakai task-success atas 20 pertanyaan analis dan SUS
dengan ambang layak ≥68. Evaluasi kinerja memakai throughput, p95 latensi
query MCP, dan latensi ringkasan. Perancangan kebutuhan, antarmuka, pengujian
fungsional, dan pengelolaan kesalahan mengikuti prinsip rekayasa perangkat
lunak [22].

### 2.3 Kerangka Pemikiran

Kerangka pemikiran proyek ini menghubungkan masalah, metode, implementasi, dan
evaluasi:

```text
Log OJS tidak terbaca
        ↓
Behavior-based detection
(frekuensi, urutan, konteks)
        ↓
Wazuh: decoder + rules + correlation + threshold
        ↓
Alert terstruktur
        ↓
MCP read-only (8 tools)
        ↓
AI Agent summarizer
        ↓
Analis: ringkasan + bukti + saran mitigasi
```

Metode berada di lapisan Wazuh (decoder, rules, correlation, threshold).
MCP dan AI Agent tidak mengubah metode deteksi; keduanya adalah lapisan
penyajian dan peringkasan. Pemisahan ini memungkinkan evaluasi deteksi dan
evaluasi ringkasan dilakukan secara terpisah.

## BAB III METODOLOGI

### 3.1 Deskripsi Solusi

Solusi yang ditawarkan terdiri atas empat lapis yang terpisah tetapi
terintegrasi:

1. **Koleksi log:** Wazuh Agent membaca log Apache OJS secara read-only.
2. **Deteksi:** Wazuh Manager menjalankan decoder dan rules perilaku OJS,
   lalu mengorelasi event dengan `frequency`, `timeframe`, dan
   `same_source_ip`.
3. **Jembatan:** MCP server read-only mengekspos alert dan metadata Wazuh
   melalui 8 tools.
4. **Summarisasi:** AI Agent merangkum alert, menjelaskan konteks, dan
   menyarankan mitigasi.

Pemisahan ini disengaja: Wazuh tetap menjadi mesin deteksi, MCP tetap menjadi
jembatan, dan AI tetap berada di luar jalur keputusan. Tidak ada auto-block
dan tidak ada tool tulis di MCP. Metode pengerjaan keseluruhan adalah
prototyping (MVP) disertai eksperimen komparatif terkontrol berpasangan [22].

Untuk menjaga etika dan reproduksibilitas, koleksi log memakai dua mode:

- **Mode deployment:** Wazuh Agent read-only pada server OJS, dengan izin
  tertulis stakeholder. Agent membaca log dan mengirimkannya ke manager.
- **Mode evaluasi:** salinan log di-replay ke Wazuh manager/agent di
  laboratorium. Mode ini dipakai untuk eksperimen yang dapat diulang.

### 3.2 Desain Sistem

Gambar 3.1 menunjukkan arsitektur sistem. Jalur data berjalan dari log OJS ke
agent, manager, indexer, MCP, lalu AI Agent. Jalur evaluasi berjalan dari
dataset terkunci ke matriks M0–M3.

```text
┌─────────────────────────────┐
│ OJS di Virtualmin           │
│ Apache access log (combined)│
└──────────────┬──────────────┘
               │ read-only
               ▼
┌─────────────────────────────┐
│ Wazuh Agent                 │
│ localfile, log_format=apache│
└──────────────┬──────────────┘
               │ 1514/tcp
               ▼
┌─────────────────────────────┐
│ Wazuh Manager               │
│ decoder + rules + correlation│
│ frequency/timeframe/srcip   │
└──────────────┬──────────────┘
               │ alerts
               ▼
┌─────────────────────────────┐
│ Wazuh Indexer + Dashboard   │
│ wazuh-alerts-*              │
└──────────────┬──────────────┘
               │ HTTPS query
               ▼
┌─────────────────────────────┐
│ MCP Server read-only        │
│ 8 tools, audit hash         │
└──────────────┬──────────────┘
               │ stdio
               ▼
┌─────────────────────────────┐
│ AI Agent (summarizer)       │
│ ringkasan + bukti + mitigasi│
└──────────────┬──────────────┘
               ▼
            Analis
```

#### 3.2.1 Bagian 1 — Koleksi log dan mode evaluasi

Wazuh Agent dikonfigurasi dengan `localfile` dan `log_format` Apache untuk
membaca file `/var/log/virtualmin/*_access_log` [7]. Agent berjalan sebagai
layanan read-only: ia tidak mengubah konfigurasi OJS, tidak menghapus log, dan
tidak melakukan pemblokiran. Pada mode evaluasi, file log disalin ke direktori
yang dipantau agent di laboratorium, sehingga urutan event dan waktu dapat
dikendalikan.

Konfigurasi laboratorium mengikuti rekomendasi quickstart Wazuh, yaitu 4 vCPU,
8 GB RAM, dan 50 GB disk untuk 1–25 agent [23]. VM proyek ini memakai 80 GB
disk agar retensi dan eksperimen tidak cepat penuh.

Pemilihan mode mengikuti Tabel 3.1.

**Tabel 3.1 Mode koleksi log.**

| Aspek | Agent langsung di OJS | Salinan log / replay |
|---|---|---|
| Real-time | Ya | Tidak |
| Perubahan produksi | Instalasi agent read-only | Tidak ada |
| Izin | Perlu izin stakeholder | Perlu akses salinan |
| Reproducibility | Lebih sulit | Tinggi |
| Nilai SOC | Penuh | Terbatas, offline |
| Penggunaan dalam TA | Arsitektur deployment | Eksperimen dan smoke test |

Rekomendasi: arsitektur final memakai agent langsung; evaluasi memakai replay.
Jika izin agent tidak tersedia, replay menjadi batasan penelitian yang
dinyatakan terbuka.

#### 3.2.2 Bagian 2 — Decoder, rules perilaku, dan ambang

Decoder memanfaatkan `web-accesslog` bawaan Wazuh untuk memecah field dasar
(`srcip`, `protocol`, `url`, `id`) [8]. Child decoder OJS ditambahkan bila
diperlukan untuk menormalkan path dan status. Rules ditulis di
`/var/ossec/etc/rules/local_rules.xml` dengan rentang ID lokal, misalnya
`100100–100199`.

Tabel 3.2 memetakan perilaku OJS yang dideteksi.

**Tabel 3.2 Pemetaan perilaku OJS.**

| Pola | Indikator perilaku | Implementasi Wazuh |
|---|---|---|
| SQLi | payload SQL di query/path, diikuti error 500/403 berulang | rule event-level + threshold |
| XSS | payload script di parameter, berulang dari sumber sama | rule event-level + threshold |
| Traversal | `../`, encoding ganda, target file galley | rule event-level + prioritas |
| XXE | akses `importexport`/`issue_galley`, unggahan XML, error parser | rule event-level + korelasi sederhana |
| Brute-force login | 401/403 berulang pada halaman login | `frequency` + `timeframe` + `same_source_ip` |
| Scanner | banyak 404/403 pada path berbeda dalam waktu singkat | threshold + variasi path |

Contoh rules behavior:

```xml
<rule id="100110" level="5">
  <if_sid>31100</if_sid>
  <url>^/index.php/.*/login</url>
  <id>^401$|^403$</id>
  <description>OJS login gagal</description>
</rule>

<rule id="100111" level="10" frequency="10" timeframe="60">
  <if_matched_sid>100110</if_matched_sid>
  <same_source_ip />
  <description>OJS brute-force: 10 login gagal dalam 60 detik</description>
</rule>
```

Rule `100110` adalah sinyal event-level. Rule `100111` adalah lapisan
behavior: ia tidak mencocokkan payload, tetapi pola pengulangan dari sumber
yang sama dalam jendela waktu. Untuk pola lain, aturan disusun dengan prinsip
serupa: satu rule untuk sinyal, satu rule untuk korelasi/ambang.

Ambang (`frequency`, `timeframe`) ditentukan pada pilot 20%, lalu dibekukan
sebelum uji 80%. Nilai ambang, versi rules, dan tanggal uji dicatat agar
eksperimen dapat direplikasi. Wazuh tidak mendukung state machine arbitrer;
karena itu, sequence yang didukung dibatasi pada rantai sederhana
`if_matched_sid`, bukan urutan bebas.

#### 3.2.3 Bagian 3 — MCP server read-only

MCP server mengekspos 8 tools read-only melalui stdio. Tools tidak menulis
ke Wazuh, tidak mengubah rules, dan tidak mengirim active response. Setiap
pemanggilan dicatat sebagai audit ber-hash argumen [11].

**Tabel 3.3 Delapan tools MCP read-only.**

| Tool | Fungsi | Sumber data |
|---|---|---|
| `rekap_harian` | rekap alert per hari/severity/rule | Indexer API |
| `top_ip_mencurigakan` | top sumber alert (hash/`/24`) | Indexer API |
| `cari_pola_serangan` | cari alert berdasarkan pola/rule group | Indexer API |
| `telusur_ip` | timeline alert untuk pseudonym IP | Indexer API |
| `korelasi_cve_ojs` | petakan alert ke CVE/rule metadata | Indexer + Server API |
| `detail_alert` | detail satu alert + bukti teredaksi | Indexer API |
| `statistik_rule` | hit count dan review false-positive | Indexer API |
| `export_laporan` | ekspor laporan teredaksi | Indexer API |

MCP memakai user Wazuh read-only dan kredensial dari environment variable,
bukan dari repository. Token JWT Wazuh Server API memiliki masa berlaku
terbatas dan di-cache sampai mendekati kedaluwarsa. Koneksi ke indexer
memakai HTTPS dan verifikasi sertifikat.

`jelaskan_insiden` dan `saran_mitigasi` tidak didaftarkan sebagai tool MCP
karena keduanya bukan query data. Keduanya adalah kemampuan AI Agent yang
memakai output tools di atas. Dengan demikian, MCP tetap menjadi bridge yang
sempit dan dapat diaudit.

#### 3.2.4 Bagian 4 — AI Agent summarizer

AI Agent menerima output MCP dalam bentuk JSON terstruktur, lalu menghasilkan
ringkasan dengan skema yang telah ditetapkan pada §2.2.6. Prompt sistem
memuat aturan: gunakan hanya data yang diberikan, sertakan `alert_ids`, jangan
mengarang fakta, dan tandai ketidakpastian. AI Agent tidak memiliki akses
langsung ke Wazuh dan tidak memiliki tool tulis.

Model, versi, dan parameter (temperature, top_p) dicatat pada log eksperimen.
Jika model gagal atau output tidak valid, sistem mengembalikan ringkasan
fallback berbasis template dan menandai kegagalan. Evaluasi ringkasan
menggunakan rubric faithfulness, completeness, actionability, clarity, dan
conciseness dengan dua penilai; tingkat kesepakatan antar-penilai dilaporkan.

#### 3.2.5 Dashboard, privasi, dan keamanan

Wazuh Dashboard dipakai sebagai antarmuka utama untuk melihat alert, tren,
dan detail rule. Dashboard Vue/MySQL dari draf lama tidak lagi menjadi inti
sistem. Jika diperlukan, halaman laporan statis dapat ditambahkan, tetapi
bukan bagian dari evaluasi utama.

Alamat IP mentah hanya disimpan di Wazuh dengan akses terbatas. MCP dan
laporan menampilkan SHA256+salt dan prefiks `/24`. Tidak ada auto-block;
kandidat blokir, jika diminta, hanya berupa teks yang harus dieksekusi manual
di luar sistem. Retensi alert dibatasi 7–14 hari untuk laboratorium, dan
konfigurasi RBAC diterapkan pada user MCP.

### 3.3 Data dan Evaluasi

#### 3.3.1 Data dan anotasi

Data dan anotasi disiapkan bertahap sesuai Tabel 3.4.

**Tabel 3.4 Data dan anotasi.**

| Komponen | Isi minimum | Fungsi |
|---|---|---|
| Log sintetis | 10.000 baris `combined` + label otomatis generator (seed tercatat) | Validasi risiko dan smoke test |
| Ground truth manual | 2–5 ribu baris dilabel analis (pola + bukti path) | Acuan presisi/recall; pilot 20% vs uji 80% |
| Sampel log produksi anonim | 50–100 ribu baris dari instalasi OJS mitra, IP di-hash + bukti teredaksi | Validasi silang + throughput |
| Agregat alert | Rekap per tanggal×pola×severity | Sumber dashboard dan tools MCP |
| Audit MCP | tool, hash argumen, hasil ringkas, latensi | Akuntabilitas dan reproduksibilitas |

Ground truth dilabel oleh dua annotator dengan panduan anotasi yang sama.
Ketidaksepakatan diselesaikan melalui adjudikasi; nilai kesepakatan
antar-annotator dilaporkan. Label disimpan terpisah dari data uji dan tidak
dilihat oleh AI Agent.

#### 3.3.2 Unit analisis

Unit analisis dibedakan menjadi dua:

- **Event:** satu baris log. Dipakai untuk mengukur aturan event-level (M1).
- **Incident:** grup `srcip + pola + time window`. Dipakai untuk mengukur
  korelasi/ambang (M2).

Pemetaan alert ke ground truth dilakukan dengan aturan yang ditetapkan
sebelum uji: alert dihitung TP jika mengenai incident yang berlabel serangan
dan memiliki bukti path/status yang sesuai; alert pada event benign dihitung
FP; incident berlabel yang tidak menghasilkan alert dihitung FN. Untuk M1,
pemetaan dilakukan pada level event. Untuk M2, pemetaan dilakukan pada level
incident. Kedua hasil dilaporkan agar tidak terjadi perbandingan yang tidak
adil.

#### 3.3.3 Matriks eksperimen

Matriks eksperimen memakai data uji yang sama dan konfigurasi yang dibekukan
(Tabel 3.5).

**Tabel 3.5 Matriks eksperimen.**

| Kode | Perlakuan | Fokus evaluasi |
|---|---|---|
| M0 | Wazuh default rules | Baseline deteksi generik |
| M1 | Custom OJS event-level rules | Kontribusi aturan perilaku OJS |
| M2 | M1 + correlation + threshold | Kontribusi korelasi/ambang |
| M3 | M2 + MCP + AI Agent | Kualitas ringkasan dan kegunaan |

M0 penting karena default ruleset Wazuh sudah memiliki aturan web generik.
M1 menguji apakah aturan OJS-spesifik menambah nilai. M2 menguji klaim utama
behavior-based detection: apakah korelasi/ambang meningkatkan deteksi insiden
dan menekan alert berlebih. M3 tidak mengubah deteksi; ia menguji apakah
ringkasan AI membantu analis memahami alert.

#### 3.3.4 Metrik dan cara pembacaan

Metrik dibaca sesuai Tabel 3.6.

**Tabel 3.6 Metrik dan cara pembacaan.**

| Metrik | Perhitungan / interpretasi |
|---|---|
| Presisi/recall/F1 per pola | TP/FP/FN vs ground truth menurut Persamaan 3.1–3.3 |
| False-positive rate | baris/insiden benign yang terlabel serang |
| Alert reduction | rasio jumlah alert M2 terhadap M0/M1 pada data uji |
| Task-success | 20 pertanyaan terjawab benar + berbukti / 20 |
| Kualitas ringkasan | rubric 1–5: faithfulness, completeness, actionability, clarity, conciseness |
| SUS | skor 5–10 analis; ambang layak ≥68 |
| Latensi | p95 query MCP dan latensi ringkasan |
| Throughput | baris/detik ingest dan alert/detik |

Persamaan yang dipakai:

```text
Presisi = TP / (TP + FP)                              (Persamaan 3.1)
Recall  = TP / (TP + FN)                              (Persamaan 3.2)
F1      = 2 × Presisi × Recall / (Presisi + Recall)    (Persamaan 3.3)
Akurasi = (TP + TN) / (TP + FP + TN + FN)              (Persamaan 3.4)
```

Keterangan: TP = true positive; FP = false positive; TN = true negative;
FN = false negative.

#### 3.3.5 Prosedur dan validitas

Prosedur evaluasi:

1. Jalankan ST4 (`wazuh-logtest`) untuk memastikan decoder dan rules bekerja
   pada sampel log.
2. Jalankan M0–M2 pada data uji yang sama; kunci versi rules dan ambang.
3. Lakukan adjudikasi hasil dan error analysis per pola.
4. Jalankan ST5 (MCP read-only) dan ST6 (ringkasan AI).
5. Ukur task-success dan SUS dengan analis.
6. Laporkan hasil event-level dan incident-level secara terpisah.

Ancaman validitas yang diakui: (a) data sintetis mungkin tidak mewakili
variasi trafik nyata; (b) ambang dapat overfit pada pilot; (c) ground truth
manusia dapat tidak konsisten; (d) LLM dapat berhalusinasi; (e) instalasi
agent di produksi dapat dibatasi kebijakan hosting; (f) log produksi hanya
berasal dari satu instalasi OJS sehingga generalisasi lintas instansi terbatas.
Mitigasi: pilot/test split, pembekuan konfigurasi, adjudikasi, guardrail AI,
dan pelaporan batasan secara terbuka.

### 3.4 Jadwal Pelaksanaan

Rencana kerja enam bulan disajikan pada Tabel 3.7.

**Tabel 3.7 Rencana kerja enam bulan.**

| Kegiatan | B1 | B2 | B3 | B4 | B5 | B6 |
|---|---|---|---|---|---|---|
| Finalisasi metode + kajian pustaka + setup Wazuh | █ | | | | | |
| Dataset + ground truth + ST4 | █ | █ | | | | |
| Rules perilaku + tuning ambang + replay | | █ | █ | | | |
| MCP 8 tools + ST5 | | | █ | | | |
| AI Agent + ST6 | | | █ | █ | | |
| Evaluasi M0–M3 + error analysis | | | | █ | █ | |
| Task-success + SUS + dashboard | | | | | █ | |
| Penulisan + revisi + pengajuan | | | | | | █ |

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

[7] Wazuh, “Wazuh server installation guide,” Wazuh Documentation 4.14,
https://documentation.wazuh.com/4.14/installation-guide/wazuh-server/index.html
(diakses Okt. 2026).

[8] Wazuh, “Ruleset XML syntax,” Wazuh Documentation,
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html
(diakses Okt. 2026).

[9] Anthropic, “Model Context Protocol Specification,”
https://modelcontextprotocol.io (diakses Okt. 2026).

[10] M. Pasternak, “ojs-mcp: MCP server for the authenticated OJS REST API,”
https://github.com/mpasternak/ojs-mcp (diakses Okt. 2026).

[11] H. Sidhpurwala, “MCP security: Logging and runtime security measures,”
Red Hat Blog, Apr. 2026.

[12] Wazuh, “Wazuh indexer API,” Wazuh Documentation,
https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html
(diakses Okt. 2026).

[13] Wazuh, “Wazuh server API reference,” Wazuh Documentation 4.14,
https://documentation.wazuh.com/4.14/user-manual/api/reference.html
(diakses Okt. 2026).

[14] GenSecAI, “Wazuh-MCP-Server,” GitHub,
https://github.com/gensecaihq/Wazuh-MCP-Server (diakses Okt. 2026).

[15] K. Scarfone and P. Mell, “Guide to Intrusion Detection and Prevention
Systems (IDPS),” NIST Special Publication 800-94, National Institute of
Standards and Technology, Gaithersburg, MD, 2007, doi:
10.6028/NIST.SP.800-94.

[16] OWASP Foundation, “OWASP ModSecurity Core Rule Set (CRS),”
https://owasp.org/projects/crs (diakses Okt. 2026).

[17] B. Sugiarto, A. Nursetyo, R. T. Subagio, Kusnadi, and P. Sokibi,
“Integration of Fail2Ban as an Artificial Intelligence Based Cyber Security
System with Random Forest Algorithm for Adaptive Detection of SSH Brute
Force Attacks,” in Proc. Cirebon Annual Multidisciplinary Int. Conf.
(CAMIC), 2026, pp. 49–53.

[18] A. Nursetyo, B. Sugiarto, Kusnadi, S. M. Saleh, and B. A. Umam,
“Pengujian Fail2Ban sebagai Mekanisme Pertahanan terhadap Serangan Brute
Force,” Jurnal Media Informatika, vol. 7, no. 1, pp. 335–343, Feb. 2026,
doi: 10.55338/jumin.v7i1.7891.

[19] R. Singh, S. Tariq, F. Jalalvand, M. Baruwal Chhetri, S. Nepal,
C. Paris, and M. Lochner, “LLMs in the SOC: An Empirical Study of Human-AI
Collaboration in Security Operations Centres,” arXiv:2508.18947, 2025.

[20] H. Okada, T. Oba, and N. Yanai, “LLMs, You Can Evaluate It! Design of
Multi-perspective Report Evaluation for Security Operation Centers,”
arXiv:2601.03013, 2026.

[21] D. M. W. Powers, “What the F-measure doesn’t measure: Features, Flaws,
Fallacies and Fixes,” Technical Report KIT-14-001, Flinders University, 2019.

[22] R. S. Pressman and B. R. Maxim, Software Engineering: A Practitioner’s
Approach, 9th ed. New York, NY: McGraw-Hill Education, 2019.

[23] Wazuh, “Quickstart,” Wazuh Documentation 4.14,
https://documentation.wazuh.com/4.14/quickstart.html (diakses Okt. 2026).
