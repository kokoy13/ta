"""Generator dataset sintetis ST1 (sekali jalan, lalu dikunci).

Output:
  - data-sintetis-st1.log : 1.000 baris format Apache combined
  - ekspektasi-st1.csv     : id_baris,label (ground truth mini ST1)

Prinsip: generator BOLEH berevolusi, file data hasil generate DIKUNCI
(hash dicatat di bawah). Skrip parser hanya membaca file, tidak membangkitkan.
Dataset evaluasi TA dilabel manual secara terpisah (Bab III) — file ini hanya
untuk validasi risiko pra-judul.
"""
import csv
import hashlib
import random

SEED = 42
N = 1000
RASIO_SERANGAN = 0.3

BENIGN = ["/", "/index.php", "/article/view/123", "/issue/view/5",
          "/public/site/images/logo.png", "/api/v1/issues", "/submissions",
          "/user/profile", "/about", "/search?query=jurnal"]
ATTACKS = [
    ("sqli", "/index.php?id=1%27%20UNION%20SELECT%201,2,3--"),
    ("xss", "/search?query=<script>alert(1)</script>"),
    ("traversal", "/plugins/importexport/native/../../etc/passwd"),
    ("xxe", "/plugins/importexport/users/import?x=<!ENTITY%20xxe>"),
    ("bruteforce_login", "/login"),
    ("scanner", "/.git/HEAD"),
    ("scanner", "/issue_galley/file.php../"),
]

random.seed(SEED)
baris_log, label = [], []
for i in range(N):
    if random.random() < RASIO_SERANGAN:
        kind, path = random.choice(ATTACKS)
        status = 401 if kind == "bruteforce_login" else (404 if kind == "scanner" else 200)
    else:
        kind, path, status = "benign", random.choice(BENIGN), 200
    baris_log.append(
        f'203.0.113.{random.randint(2, 250)} - - '
        f'[10/Oct/2026:13:{i % 60:02d}:{i % 60:02d} +0700] '
        f'"GET {path} HTTP/1.1" {status} 1234 "-" "Mozilla/5.0"'
    )
    label.append((i, kind))

with open("data-sintetis-st1.log", "w") as f:
    f.write("\n".join(baris_log) + "\n")
with open("ekspektasi-st1.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["id_baris", "label"])
    w.writerows(label)

for nama in ("data-sintetis-st1.log", "ekspektasi-st1.csv"):
    h = hashlib.sha256(open(nama, "rb").read()).hexdigest()
    print(f"{nama}: sha256={h}")
print(f"ST-GEN: {N} baris log + {N} label ditulis.")
