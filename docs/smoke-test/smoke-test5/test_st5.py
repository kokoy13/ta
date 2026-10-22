from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from wazuh_readonly import WRITE_TOOLS, WazuhReadOnly

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "alerts.json"


def main() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    hits = payload["hits"]["hits"]
    client = WazuhReadOnly(mock_alerts=hits, salt="st5-test-salt")

    rekap = client.rekap_harian("2026-10-21", "2026-10-22")
    assert len(rekap) == 7, rekap
    assert {row["rule_id"] for row in rekap} == {
        "100102",
        "100110",
        "100130",
        "100111",
        "100120",
        "100121",
        "100113",
    }

    top_ip = client.top_ip_mencurigakan(limit=3)
    assert len(top_ip) == 3
    assert all(len(row["ip_hash"]) == 16 for row in top_ip)
    assert all(row["ip_prefix"] == "203.0.113.0/24" for row in top_ip)

    brute = client.cari_pola_serangan("bruteforce")
    assert len(brute) == 1
    assert brute[0]["_id"] == "alert-1"

    timeline = client.telusur_ip("203.0.113.10")
    assert len(timeline) == 1
    assert timeline[0]["rule_id"] == "100102"
    assert timeline[0]["ip_hash"]

    cve = client.korelasi_cve_ojs("CVE-2024-56525")
    assert len(cve) == 1
    assert cve[0]["_id"] == "alert-4"

    detail = client.detail_alert("alert-1")
    assert detail is not None
    assert detail["_id"] == "alert-1"
    assert "full_log" not in detail["_source"]

    stats = client.statistik_rule()
    assert len(stats) == 7
    assert sum(row["count"] for row in stats) == 7

    report = client.export_laporan()
    report_payload = json.loads(report)
    assert report_payload["count"] == 7
    assert "203.0.113.10" not in report
    assert "203.0.113.20" not in report

    combined = json.dumps(
        {
            "rekap": rekap,
            "top_ip": top_ip,
            "brute": brute,
            "timeline": timeline,
            "cve": cve,
            "detail": detail,
            "stats": stats,
            "report": report,
        },
        ensure_ascii=False,
    )
    for raw_ip in ("203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40"):
        assert raw_ip not in combined, raw_ip

    assert WRITE_TOOLS == frozenset()
    assert not hasattr(client, "active_response")
    assert not hasattr(client, "block_ip")
    assert not hasattr(client, "write_rule")

    assert len(client.audit_log) == 8
    assert all(len(entry["args_hash"]) == 64 for entry in client.audit_log)
    audit_json = json.dumps(client.audit_log)
    assert "203.0.113.10" not in audit_json
    assert "203.0.113.20" not in audit_json

    first_hash = client.audit_log[0]["args_hash"]
    client.rekap_harian("2026-10-21", "2026-10-22")
    assert client.audit_log[-1]["args_hash"] == first_hash

    with tempfile.TemporaryDirectory() as tmp:
        dict_path = Path(tmp) / "dict.json"
        list_path = Path(tmp) / "list.json"
        dict_path.write_text(json.dumps(payload), encoding="utf-8")
        list_path.write_text(json.dumps(hits), encoding="utf-8")
        os.environ["WAZUH_MOCK_FILE"] = str(dict_path)
        assert len(WazuhReadOnly.from_env().mock_alerts or []) == 7
        os.environ["WAZUH_MOCK_FILE"] = str(list_path)
        assert len(WazuhReadOnly.from_env().mock_alerts or []) == 7
        os.environ.pop("WAZUH_MOCK_FILE", None)

    print("ST5 PASS")
    print(f"tools_checked={8} audit_events={len(client.audit_log)} write_tools={len(WRITE_TOOLS)}")
    print(f"top_ip_hash={top_ip[0]['ip_hash']} prefix={top_ip[0]['ip_prefix']}")


if __name__ == "__main__":
    main()
