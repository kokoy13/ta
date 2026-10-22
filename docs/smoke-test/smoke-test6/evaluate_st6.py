from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from summarizer import IP_RE, normalize_alerts, validate_summary

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _allowed_ip(text: str, start: int, end: int) -> bool:
    token = text[start:end]
    return token.endswith(".0") and text[end : end + 3] == "/24"


def _has_disallowed_ip(text: str) -> bool:
    return any(not _allowed_ip(text, match.start(), match.end()) for match in IP_RE.finditer(text))


def evaluate_summary(summary: dict[str, Any], payload: Any) -> dict[str, Any]:
    alerts = normalize_alerts(payload)
    input_ids = {alert["alert_id"] for alert in alerts}
    input_cves = {str(alert["cve"]) for alert in alerts if alert.get("cve")}
    summary_text = json.dumps(summary, ensure_ascii=False)
    mitigations = " ".join(str(item) for item in summary.get("mitigasi", [])).lower()

    errors = validate_summary(summary)
    alert_ids_valid = set(summary.get("alert_ids", [])) <= input_ids
    cves_in_summary = set(CVE_RE.findall(summary_text))
    cve_grounded = cves_in_summary <= input_cves
    no_raw_ip = not _has_disallowed_ip(summary_text)
    no_auto_block = not any(
        phrase in mitigations
        for phrase in ("blokir otomatis", "otomatis memblokir", "auto-block", "autoblock")
    )

    ringkasan_words = len(str(summary.get("ringkasan", "")).split())
    completeness_fields = all(
        bool(summary.get(key))
        for key in ("ringkasan", "severity", "indikator", "dampak", "mitigasi", "alert_ids")
    )

    scores = {
        "faithfulness": 5 if not errors and alert_ids_valid and cve_grounded and no_raw_ip else 1,
        "completeness": 5 if completeness_fields and len(summary.get("indikator", [])) >= 1 else 3 if completeness_fields else 1,
        "actionability": 5 if len(summary.get("mitigasi", [])) >= 3 and no_auto_block else 3 if summary.get("mitigasi") else 1,
        "clarity": 5 if 15 <= ringkasan_words <= 120 else 3 if ringkasan_words <= 180 else 1,
        "conciseness": 5
        if len(summary.get("indikator", [])) <= 6 and len(summary.get("mitigasi", [])) <= 6
        else 3
        if len(summary.get("indikator", [])) <= 10
        else 1,
    }

    return {
        "scores": scores,
        "checks": {
            "schema_errors": errors,
            "alert_ids_valid": alert_ids_valid,
            "cve_grounded": cve_grounded,
            "no_raw_ip": no_raw_ip,
            "no_auto_block": no_auto_block,
            "ringkasan_words": ringkasan_words,
        },
    }


def main() -> None:
    root = Path(__file__).resolve().parent
    payload = json.loads((root / "fixtures" / "alerts_input.json").read_text(encoding="utf-8"))
    summary_path = root / "hasil-st6.json"
    if not summary_path.exists():
        raise SystemExit("hasil-st6.json belum ada. Jalankan test_st6.py atau summarizer.py dulu.")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    print(json.dumps(evaluate_summary(summary, payload), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
