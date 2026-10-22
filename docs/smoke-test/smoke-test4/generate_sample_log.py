from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path

BASE = datetime(2026, 10, 21, 10, 0, 0)
ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "sample-ojs.log"
EXPECTED_PATH = ROOT / "expected-results.csv"

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"


def ts(offset: int) -> str:
    return (BASE + timedelta(seconds=offset)).strftime("%d/%b/%Y:%H:%M:%S +0700")


def line(ip: str, method: str, path: str, status: int, offset: int) -> str:
    return f'{ip} - - [{ts(offset)}] "{method} {path} HTTP/1.1" {status} 512 "-" "{UA}"'


def main() -> None:
    rows: list[tuple[int, str, str, str]] = []
    lines: list[str] = []

    benign = [
        ("198.51.100.10", "/index.php/ojs", 200),
        ("198.51.100.10", "/index.php/ojs/issue/archive", 200),
        ("198.51.100.11", "/index.php/ojs/issue/view/1", 200),
        ("198.51.100.11", "/index.php/ojs/article/view/1", 200),
        ("198.51.100.12", "/index.php/ojs/login", 200),
    ]
    for index, (ip, path, status) in enumerate(benign):
        lines.append(line(ip, "GET", path, status, index))
        rows.append((len(lines), "benign", "-", "no alert"))

    for index in range(10):
        lines.append(line("203.0.113.10", "POST", "/index.php/ojs/login", 401, 10 + index))
        rule = "100101" if index < 9 else "100101,100102"
        rows.append((len(lines), "bruteforce_login", rule, "rule 100102 pada event ke-10"))

    lines.append(line("203.0.113.20", "GET", "/index.php/ojs/issue/view/1?file=../../../../etc/passwd", 403, 100))
    rows.append((len(lines), "traversal", "100110", "event-level"))

    for offset in (110, 120):
        lines.append(line("203.0.113.21", "GET", "/index.php/ojs/issue/view/2?file=../../../../etc/passwd", 403, offset))
        rule = "100110" if offset == 110 else "100110,100130"
        rows.append((len(lines), "traversal_repeat", rule, "rule 100130 pada event kedua"))

    lines.append(line("203.0.113.30", "POST", "/index.php/ojs/management/importexport/plugin", 200, 130))
    rows.append((len(lines), "xxe_importexport", "100111", "event-level"))

    lines.append(line("203.0.113.40", "GET", "/index.php/ojs/article/view/1?id=1%20UNION%20SELECT%20password%20FROM%20users", 500, 140))
    rows.append((len(lines), "sqli", "100120", "event-level"))

    lines.append(line("203.0.113.50", "GET", "/index.php/ojs/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, 150))
    rows.append((len(lines), "xss", "100121", "event-level"))

    for index in range(20):
        lines.append(line("203.0.113.60", "GET", f"/index.php/ojs/admin/probe{index}", 404, 160 + index))
        rule = "100112" if index < 19 else "100112,100113"
        rows.append((len(lines), "scanner", rule, "rule 100113 pada event ke-20"))

    LOG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with EXPECTED_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["line", "scenario", "expected_rule", "note"])
        writer.writerows(rows)

    print(f"wrote {len(lines)} lines to {LOG_PATH}")
    print(f"wrote expected results to {EXPECTED_PATH}")


if __name__ == "__main__":
    main()
