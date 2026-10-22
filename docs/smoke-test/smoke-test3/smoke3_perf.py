"""Smoke-test 3: import 100rb baris sintetis -> SQLite + uji waktu query.

Tujuan: validasi risiko SKALA (bukan ketepatan — itu milik ST1/Bab IV).
Pertanyaan yang dijawab: "apakah 1 juta log/bulan muat di laptop?"
Hasil run: import 0,9 dtk (ambang 600), query 0-50 mdetik (ambang 3.000).
Margin 60-10.000x -> proyeksi skala produksi aman di SQLite laptop.
"""
# Hanya stdlib (re/random/sqlite3/time/hashlib): bukti "tanpa GPU, tanpa server DB".
import re, random, sqlite3, time, hashlib

# Mesin SAMA dengan ST1 (disengaja — konsistensi rantai uji). Bedanya di sini
# berbentuk list berurutan = cermin keputusan prioritas ST1 (traversal dulu).
# seed(7) beda dari ST1 agar distribusi independen; 15% serangan (vs 30% di ST1)
# agar mirip trafik nyata yang mayoritas benign.
COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)
RULES = [
    ("sqli", re.compile(r"(%27|'|%22).*(union|select|or\s+1\s*=\s*1)", re.I)),
    ("xss", re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("traversal", re.compile(r"(\.\./|%2e%2e|/etc/passwd)", re.I)),
    ("xxe", re.compile(r"(<!ENTITY|DOCTYPE.*\[|importexport)", re.I)),
    ("bruteforce_login", re.compile(r"(login|signin|wp-login)", re.I)),
    ("scanner", re.compile(r"(\.git/|\.env|phpmyadmin|xmlrpc\.php)", re.I)),
]
random.seed(7)
BENIGN = ["/", "/index.php", "/article/view/123", "/issue/view/5", "/api/v1/issues", "/search?query=jurnal"]
ATK = ["/x?id=1%27%20UNION%20SELECT%201--", "/s?q=<script>x</script>", "/p/../../etc/passwd",
       "/plugins/importexport/x", "/login", "/.git/HEAD", "/wp-login.php"]

con = sqlite3.connect(":memory:")
con.execute("CREATE TABLE log_raw(ts TEXT, ip_hash TEXT, method TEXT, path TEXT, status INT, pola TEXT)")
# INDEKS inilah jawaban atas "kenapa query cepat": tanpa idx_pola, GROUP BY pola
# atas 100rb baris memindai penuh. Di produk final ditambah indeks ip_hash/ts.
con.execute("CREATE INDEX idx_pola ON log_raw(pola)")

t0 = time.time()
batch = []
for i in range(100000):
    if random.random() < 0.15:
        path, status = random.choice(ATK), random.choice([200, 401, 403, 404])
    else:
        path, status = random.choice(BENIGN), 200
    ip = f"203.0.113.{random.randint(2,250)}"
    # Tiga keputusan produksi dalam satu baris: (a) IP langsung di-hash SAAT
    # INGEST (anonimisasi sejak pintu masuk, bukan tempelan); (b) label pola
    # ditetapkan saat ingest sehingga query baca tinggal agregasi (pemisahan
    # jalur tulis ST1 vs jalur baca ST2); (c) batch 5000 + satu commit
    # (puluhan kali lebih cepat dari commit per baris).
    batch.append((f"2026-10-07 13:{i%60:02d}", hashlib.sha256(ip.encode()).hexdigest()[:16], "GET", path, status,
                  next((k for k, rx in RULES if rx.search(path)), "benign")))
    if len(batch) == 5000:
        con.executemany("INSERT INTO log_raw VALUES (?,?,?,?,?,?)", batch)
        batch = []
con.executemany("INSERT INTO log_raw VALUES (?,?,?,?,?,?)", batch)
con.commit()
t_import = time.time() - t0

def timed(q, args=()):
    # Timer dinding-waktu per query = cikal-bakal metrik "p95" di Bab IV
    # (di sana diulang N kali secara statistik; di sini sekali jalan).
    qs = time.time()
    r = con.execute(q, args).fetchall()
    return time.time() - qs, r

qs = []
# Empat query = cermin 4 kebutuhan tool/dashboard final:
d, r = timed("SELECT pola, COUNT(*), COUNT(DISTINCT ip_hash) FROM log_raw GROUP BY pola ORDER BY 2 DESC"); qs.append(("agregat", d))  # = rekap_harian
d, r2 = timed("SELECT path, COUNT(*) c FROM log_raw WHERE pola='bruteforce_login' GROUP BY path ORDER BY c DESC LIMIT 10"); qs.append(("top-path-bf", d))  # = telusur_ip
d, r3 = timed("SELECT * FROM log_raw WHERE pola='traversal' LIMIT 20"); qs.append(("drilldown", d))  # = bukti dashboard
d, r4 = timed("SELECT COUNT(*) FROM log_raw WHERE status IN (401,403)"); qs.append(("hitung-401", d))  # = sinyal brute-force
n = con.execute("SELECT COUNT(*) FROM log_raw").fetchone()[0]
print(f"ST3 import 100rb: {t_import:.1f}s, total tersimpan={n}")
for name, d in qs:
    print(f"ST3 query {name:14s}: {d*1000:.0f}ms")
# Ambang LONGGAR sengaja (validasi risiko, bukan benchmark): import <600 dtk,
# query <3 dtk. Yang penting marginnya besar.
ok = t_import < 600 and all(d < 3 for _, d in qs)
print("ST3 RESULT:", "LULUS" if ok else "GAGAL")
# BATAS ST3 (seminar): DB :memory: (produk final pakai file + 4 tabel, angka
# akan naik tapi margin 60-10.000x menutupinya — Bab IV ukur ulang di DB file);
# distribusi sintetis seragam (log real miring; indeks ip_hash/ts menyusul);
# sekali jalan (p95 statistik di Bab IV).
