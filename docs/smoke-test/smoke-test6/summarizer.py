from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
PROMPT_PATH = ROOT / "prompt.md"

REQUIRED_KEYS = (
    "ringkasan",
    "severity",
    "indikator",
    "dampak",
    "mitigasi",
    "alert_ids",
    "ketidakpastian",
)
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def normalize_alerts(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        raw = payload
    elif isinstance(payload, dict) and isinstance(payload.get("alerts"), list):
        raw = payload["alerts"]
    elif isinstance(payload, dict) and isinstance(payload.get("hits"), dict):
        raw = payload["hits"].get("hits", [])
    else:
        raise ValueError("Input harus list alert, {alerts: [...]}, atau respons Wazuh {hits: {...}}.")

    alerts: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        source = item.get("_source", item)
        rule = source.get("rule", {}) if isinstance(source.get("rule"), dict) else {}
        data = source.get("data", {}) if isinstance(source.get("data"), dict) else {}
        alerts.append(
            {
                "alert_id": str(item.get("_id", source.get("alert_id", "unknown"))),
                "timestamp": source.get("timestamp"),
                "rule_id": str(rule.get("id", source.get("rule_id", "-"))),
                "level": int(rule.get("level", source.get("level", 0)) or 0),
                "description": str(rule.get("description", source.get("description", ""))),
                "url": data.get("url", source.get("url")),
                "status": str(data.get("id", source.get("status", ""))),
                "ip_hash": data.get("srcip_hash", source.get("ip_hash")),
                "ip_prefix": data.get("srcip_prefix", source.get("ip_prefix")),
                "cve": data.get("cve", source.get("cve")),
            }
        )
    return alerts


def severity_from_level(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _unique(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def summarize_template(payload: Any) -> dict[str, Any]:
    alerts = normalize_alerts(payload)
    if not alerts:
        return {
            "ringkasan": "Tidak ada alert OJS pada data yang diberikan.",
            "severity": "low",
            "indikator": [],
            "dampak": "Tidak ada indikasi serangan yang dapat disimpulkan.",
            "mitigasi": ["Tidak ada tindakan yang diperlukan berdasarkan data ini."],
            "alert_ids": [],
            "ketidakpastian": "Tidak ada data alert; ringkasan tidak dapat diverifikasi.",
        }

    max_level = max(alert["level"] for alert in alerts)
    descriptors = Counter(alert["description"] for alert in alerts if alert["description"])
    top_description, top_count = descriptors.most_common(1)[0] if descriptors else ("-", 0)
    hashes = _unique([alert["ip_hash"] for alert in alerts])
    cves = _unique([alert["cve"] for alert in alerts])
    urls = _unique([alert["url"] for alert in alerts])
    alert_ids = _unique([alert["alert_id"] for alert in alerts])

    severity = severity_from_level(max_level)
    ringkasan = (
        f"Terdeteksi {len(alerts)} alert OJS dengan severity {severity}. "
        f"Pola dominan: {top_description} ({top_count} alert). "
        f"Sumber unik (hash): {len(hashes)}."
    )
    indikator = [
        f"{alert['description']} pada {alert['url']} "
        f"(status {alert['status'] or '-'}, level {alert['level']})"
        for alert in alerts[:5]
    ]
    if urls:
        indikator.append(f"URL yang terlibat: {', '.join(urls[:5])}")

    dampak = (
        "Berpotensi mengganggu kerahasiaan, integritas, atau ketersediaan "
        "layanan OJS apabila alert terkonfirmasi sebagai serangan."
    )
    if cves:
        dampak += f" Alert terkait {', '.join(cves)}."

    mitigasi = [
        "Verifikasi alert terhadap log mentah dan konteks trafik terkait.",
        "Tinjau apakah ada indikasi keberhasilan eksploitasi atau perubahan konfigurasi.",
        "Jika terkonfirmasi, lakukan pemblokiran manual di luar sistem (tidak otomatis).",
        "Perbarui OJS ke rilis yang diperbaiki dan tinjau hardening endpoint terkait.",
    ]

    return {
        "ringkasan": ringkasan,
        "severity": severity,
        "indikator": indikator,
        "dampak": dampak,
        "mitigasi": mitigasi,
        "alert_ids": alert_ids,
        "ketidakpastian": (
            "Ringkasan disusun hanya dari alert yang diberikan MCP; "
            "belum diverifikasi terhadap log mentah atau wawancara analis."
        ),
    }


def validate_summary(summary: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_KEYS:
        if key not in summary:
            errors.append(f"missing:{key}")
    if summary.get("severity") not in ALLOWED_SEVERITY:
        errors.append("invalid:severity")
    for key in ("indikator", "mitigasi", "alert_ids"):
        if not isinstance(summary.get(key), list):
            errors.append(f"not_list:{key}")
    return errors


def _strip_code_fence(text: str) -> str:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return cleaned


def parse_llm_json(text: str) -> dict[str, Any]:
    payload = json.loads(_strip_code_fence(text))
    if not isinstance(payload, dict):
        raise ValueError("Output LLM bukan objek JSON.")
    errors = validate_summary(payload)
    if errors:
        raise ValueError(f"Output LLM tidak lengkap: {errors}")
    return payload


def call_llm(payload: Any) -> dict[str, Any]:
    base_url = os.environ.get("LLM_BASE_URL")
    api_key = os.environ.get("LLM_API_KEY")
    model = os.environ.get("LLM_MODEL")
    if not base_url or not api_key or not model:
        raise RuntimeError("Set LLM_BASE_URL, LLM_API_KEY, dan LLM_MODEL untuk mode llm.")

    system_prompt = PROMPT_PATH.read_text(encoding="utf-8")
    user_payload = json.dumps(payload, ensure_ascii=False)
    body = json.dumps(
        {
            "model": model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
            ],
        },
        ensure_ascii=False,
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        completion = json.loads(response.read().decode("utf-8"))
    content = completion["choices"][0]["message"]["content"]
    return parse_llm_json(content)


def summarize(payload: Any, mode: str = "template") -> dict[str, Any]:
    if mode == "template":
        return summarize_template(payload)
    if mode != "llm":
        raise ValueError("mode harus template atau llm")
    try:
        return call_llm(payload)
    except Exception as exc:
        fallback = summarize_template(payload)
        fallback["ketidakpastian"] += f" Fallback template dipakai karena LLM gagal: {exc}."
        return fallback


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="File JSON alert dari MCP")
    parser.add_argument("--output", help="File JSON ringkasan")
    parser.add_argument("--mode", choices=("template", "llm"), default="template")
    args = parser.parse_args()

    payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
    summary = summarize(payload, args.mode)
    text = json.dumps(summary, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
