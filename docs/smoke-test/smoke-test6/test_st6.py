from __future__ import annotations

import json
from pathlib import Path

from evaluate_st6 import evaluate_summary
from summarizer import parse_llm_json, summarize_template, validate_summary

ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / "fixtures" / "alerts_input.json"
OUTPUT = ROOT / "hasil-st6.json"


def main() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    summary = summarize_template(payload)

    errors = validate_summary(summary)
    assert not errors, errors
    assert summary["severity"] == "high"
    assert set(summary["alert_ids"]) == {"alert-1", "alert-2", "alert-4"}
    assert "CVE-2024-56525" in json.dumps(summary, ensure_ascii=False)
    assert "203.0.113.10" not in json.dumps(summary, ensure_ascii=False)
    assert "blokir otomatis" not in " ".join(summary["mitigasi"]).lower()

    evaluation = evaluate_summary(summary, payload)
    assert evaluation["checks"]["alert_ids_valid"] is True
    assert evaluation["checks"]["cve_grounded"] is True
    assert evaluation["checks"]["no_raw_ip"] is True
    assert evaluation["checks"]["no_auto_block"] is True
    assert evaluation["scores"]["faithfulness"] == 5
    assert evaluation["scores"]["completeness"] == 5
    assert evaluation["scores"]["actionability"] >= 4

    empty = summarize_template({"alerts": []})
    assert empty["severity"] == "low"
    assert empty["alert_ids"] == []
    assert validate_summary(empty) == []

    fenced = "```json\n" + json.dumps(summary, ensure_ascii=False) + "\n```"
    parsed = parse_llm_json(fenced)
    assert parsed == summary

    again = summarize_template(payload)
    assert again == summary

    OUTPUT.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print("ST6 PASS")
    print(f"scores={evaluation['scores']}")
    print(f"output={OUTPUT}")


if __name__ == "__main__":
    main()
