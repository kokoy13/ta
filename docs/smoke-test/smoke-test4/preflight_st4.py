from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RULES = ROOT / "local_rules.xml"
SAMPLE = ROOT / "sample-ojs.log"
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) HTTP/[^"]+" (\d{3}) ')


def load_rules() -> dict[str, ET.Element]:
    root = ET.parse(RULES).getroot()
    rules = {rule.get("id", ""): rule for rule in root.findall("rule")}
    assert len(rules) == len(root.findall("rule")), "duplicate rule id"
    assert all(rule_id.startswith("100") for rule_id in rules), "unexpected rule id"
    return rules


def matches(
    rule: ET.Element,
    url: str,
    status: str,
    rules: dict[str, ET.Element],
) -> bool:
    url_pattern = rule.findtext("url")
    id_pattern = rule.findtext("id")
    if url_pattern and not re.search(url_pattern, url):
        return False
    if id_pattern and not re.search(id_pattern, status):
        return False
    parent = rule.findtext("if_sid")
    if parent in rules and not matches(rules[parent], url, status, rules):
        return False
    return True


def parse_sample() -> list[dict[str, str]]:
    rows = []
    for line in SAMPLE.read_text(encoding="utf-8").splitlines():
        match = LOG_RE.match(line)
        assert match, f"unparsed log line: {line}"
        ip, timestamp, method, url, status = match.groups()
        rows.append(
            {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "url": url,
                "status": status,
            }
        )
    return rows


def window_ok(rows: list[dict[str, str]], seconds: int) -> bool:
    times = [datetime.strptime(row["timestamp"], "%d/%b/%Y:%H:%M:%S %z") for row in rows]
    return (max(times) - min(times)).total_seconds() <= seconds


def main() -> None:
    rules = load_rules()
    rows = parse_sample()
    assert len(rows) == 41, len(rows)

    counts = Counter()
    for row in rows:
        for rule_id, rule in rules.items():
            if matches(rule, row["url"], row["status"], rules):
                counts[rule_id] += 1

    expected = {
        "100100": 11,
        "100101": 10,
        "100110": 3,
        "100111": 1,
        "100112": 20,
        "100120": 1,
        "100121": 1,
    }
    for rule_id, count in expected.items():
        assert counts[rule_id] == count, (rule_id, counts[rule_id], count)

    brute = [row for row in rows if row["ip"] == "203.0.113.10" and row["status"] == "401"]
    scanner = [row for row in rows if row["ip"] == "203.0.113.60" and row["status"] == "404"]
    traversal = [row for row in rows if row["ip"] == "203.0.113.21" and "etc/passwd" in row["url"]]
    importexport = [row for row in rows if "importexport" in row["url"]]

    assert len(brute) == 10 and window_ok(brute, 60), "brute-force window"
    assert len(scanner) == 20 and window_ok(scanner, 60), "scanner window"
    assert len(traversal) == 2 and window_ok(traversal, 300), "traversal window"
    assert len(importexport) == 1, "importexport should not trigger repeated rule"

    print("ST4 PREFLIGHT PASS")
    print(f"rules={len(rules)} lines={len(rows)} event_counts={dict(expected)}")
    print("correlation=100102,100113,100130; 100131=not-triggered")


if __name__ == "__main__":
    main()
