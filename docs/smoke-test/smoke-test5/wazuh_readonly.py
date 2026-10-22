from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import ssl
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

WRITE_TOOLS: frozenset[str] = frozenset()
DEFAULT_SALT = "dev-salt-change-me"


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_ts(value: str) -> datetime:
    cleaned = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _in_range(value: str, date_from: str | None, date_to: str | None) -> bool:
    current = _parse_ts(value).date()
    if date_from and current < datetime.fromisoformat(date_from).date():
        return False
    if date_to and current > datetime.fromisoformat(date_to).date():
        return False
    return True


def _mask_ip(ip: str, salt: str) -> tuple[str, str]:
    digest = hashlib.sha256(f"{salt}:{ip}".encode("utf-8")).hexdigest()[:16]
    parts = ip.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    else:
        prefix = "unknown"
    return digest, prefix


def _redact(value: Any, salt: str) -> Any:
    if isinstance(value, list):
        return [_redact(item, salt) for item in value]
    if not isinstance(value, dict):
        return value

    result: dict[str, Any] = {}
    for key, item in value.items():
        if key == "full_log":
            continue
        if key in {"srcip", "srcip2", "dstip"} and isinstance(item, str):
            digest, prefix = _mask_ip(item, salt)
            result[f"{key}_hash"] = digest
            result[f"{key}_prefix"] = prefix
            continue
        result[key] = _redact(item, salt)
    return result


def _source(alert: dict[str, Any]) -> dict[str, Any]:
    source = alert.get("_source")
    return source if isinstance(source, dict) else {}


def _rule(source: dict[str, Any]) -> dict[str, Any]:
    rule = source.get("rule")
    return rule if isinstance(rule, dict) else {}


def _data(source: dict[str, Any]) -> dict[str, Any]:
    data = source.get("data")
    return data if isinstance(data, dict) else {}


def _matches_text(alert: dict[str, Any], needle: str) -> bool:
    source = _source(alert)
    rule = _rule(source)
    data = _data(source)
    haystack = " ".join(
        [
            str(rule.get("description", "")),
            " ".join(str(item) for item in rule.get("groups", [])),
            str(data.get("url", "")),
            str(data.get("cve", "")),
        ]
    ).lower()
    return needle.lower() in haystack


@dataclass
class WazuhReadOnly:
    indexer_url: str | None = None
    indexer_user: str | None = None
    indexer_password: str | None = None
    verify_tls: bool = True
    mock_alerts: list[dict[str, Any]] | None = None
    salt: str = DEFAULT_SALT
    timeout: int = 30
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "WazuhReadOnly":
        mock_file = os.environ.get("WAZUH_MOCK_FILE")
        salt = os.environ.get("OJS_PSEUDONYM_SALT", DEFAULT_SALT)
        if mock_file:
            payload = json.loads(Path(mock_file).read_text(encoding="utf-8"))
            if isinstance(payload, list):
                hits = payload
            elif isinstance(payload, dict) and isinstance(payload.get("hits"), dict):
                hits = payload["hits"].get("hits", [])
            else:
                hits = []
            return cls(mock_alerts=hits, salt=salt)
        return cls(
            indexer_url=os.environ.get("WAZUH_INDEXER_URL"),
            indexer_user=os.environ.get("WAZUH_INDEXER_USER"),
            indexer_password=os.environ.get("WAZUH_INDEXER_PASSWORD"),
            verify_tls=os.environ.get("WAZUH_VERIFY_TLS", "1") not in {"0", "false", "False"},
            salt=salt,
        )

    def _audit(self, tool: str, arguments: dict[str, Any]) -> None:
        self.audit_log.append(
            {
                "tool": tool,
                "args_hash": _canonical_hash(arguments),
                "arg_keys": sorted(arguments),
            }
        )

    def _search(self, size: int = 1000) -> list[dict[str, Any]]:
        if self.mock_alerts is not None:
            return copy.deepcopy(self.mock_alerts[:size])
        if not self.indexer_url or not self.indexer_user or not self.indexer_password:
            raise RuntimeError(
                "Set WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD "
                "atau WAZUH_MOCK_FILE."
            )
        body = json.dumps(
            {"size": size, "sort": [{"timestamp": {"order": "desc"}}]},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.indexer_url.rstrip('/')}/wazuh-alerts-*/_search",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        token = base64.b64encode(
            f"{self.indexer_user}:{self.indexer_password}".encode("utf-8")
        ).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
        context = ssl.create_default_context()
        if not self.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(request, context=context, timeout=self.timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return payload.get("hits", {}).get("hits", [])

    def _filtered(
        self,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        alerts = self._search()
        return [
            alert
            for alert in alerts
            if _in_range(str(_source(alert).get("timestamp", "")), date_from, date_to)
        ]

    def rekap_harian(
        self,
        date_from: str | None = None,
        date_to: str | None = None,
        severity_min: int = 0,
    ) -> list[dict[str, Any]]:
        self._audit("rekap_harian", {"date_from": date_from, "date_to": date_to, "severity_min": severity_min})
        buckets: dict[tuple[str, str, int], int] = {}
        descriptions: dict[tuple[str, str, int], str] = {}
        for alert in self._filtered(date_from, date_to):
            source = _source(alert)
            rule = _rule(source)
            level = int(rule.get("level", 0))
            if level < severity_min:
                continue
            date = str(source.get("timestamp", ""))[:10]
            rule_id = str(rule.get("id", "-"))
            key = (date, rule_id, level)
            buckets[key] = buckets.get(key, 0) + 1
            descriptions[key] = str(rule.get("description", ""))
        return [
            {
                "date": key[0],
                "rule_id": key[1],
                "level": key[2],
                "description": descriptions[key],
                "count": count,
            }
            for key, count in sorted(buckets.items(), key=lambda item: (item[0][0], -item[0][2], item[0][1]))
        ]

    def top_ip_mencurigakan(
        self,
        limit: int = 10,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        self._audit("top_ip_mencurigakan", {"limit": limit, "date_from": date_from, "date_to": date_to})
        buckets: dict[str, dict[str, Any]] = {}
        for alert in self._filtered(date_from, date_to):
            data = _data(_source(alert))
            raw_ip = data.get("srcip")
            if not isinstance(raw_ip, str):
                continue
            digest, prefix = _mask_ip(raw_ip, self.salt)
            entry = buckets.setdefault(
                digest,
                {"ip_hash": digest, "ip_prefix": prefix, "count": 0, "rule_ids": set()},
            )
            entry["count"] += 1
            entry["rule_ids"].add(str(_rule(_source(alert)).get("id", "-")))
        result = [
            {
                "ip_hash": entry["ip_hash"],
                "ip_prefix": entry["ip_prefix"],
                "count": entry["count"],
                "rule_ids": sorted(entry["rule_ids"]),
            }
            for entry in buckets.values()
        ]
        return sorted(result, key=lambda item: (-item["count"], item["ip_hash"]))[:limit]

    def cari_pola_serangan(
        self,
        pola: str,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        self._audit("cari_pola_serangan", {"pola": pola, "date_from": date_from, "date_to": date_to, "limit": limit})
        matches = [
            _redact(alert, self.salt)
            for alert in self._filtered(date_from, date_to)
            if _matches_text(alert, pola)
        ]
        return matches[:limit]

    def telusur_ip(
        self,
        ip: str,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        self._audit("telusur_ip", {"ip": ip, "date_from": date_from, "date_to": date_to})
        timeline = []
        for alert in self._filtered(date_from, date_to):
            data = _data(_source(alert))
            if data.get("srcip") != ip:
                continue
            redacted = _redact(alert, self.salt)
            source = _source(redacted)
            timeline.append(
                {
                    "alert_id": redacted.get("_id"),
                    "timestamp": source.get("timestamp"),
                    "rule_id": _rule(source).get("id"),
                    "level": _rule(source).get("level"),
                    "description": _rule(source).get("description"),
                    "url": _data(source).get("url"),
                    "ip_hash": _data(source).get("srcip_hash"),
                    "ip_prefix": _data(source).get("srcip_prefix"),
                }
            )
        return sorted(timeline, key=lambda item: str(item.get("timestamp", "")))

    def korelasi_cve_ojs(
        self,
        cve: str,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        self._audit("korelasi_cve_ojs", {"cve": cve, "date_from": date_from, "date_to": date_to, "limit": limit})
        matches = [
            _redact(alert, self.salt)
            for alert in self._filtered(date_from, date_to)
            if _matches_text(alert, cve)
        ]
        return matches[:limit]

    def detail_alert(self, alert_id: str) -> dict[str, Any] | None:
        self._audit("detail_alert", {"alert_id": alert_id})
        for alert in self._search():
            if alert.get("_id") == alert_id:
                return _redact(alert, self.salt)
        return None

    def statistik_rule(
        self,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        self._audit("statistik_rule", {"date_from": date_from, "date_to": date_to})
        buckets: dict[str, dict[str, Any]] = {}
        for alert in self._filtered(date_from, date_to):
            rule = _rule(_source(alert))
            rule_id = str(rule.get("id", "-"))
            entry = buckets.setdefault(
                rule_id,
                {
                    "rule_id": rule_id,
                    "description": str(rule.get("description", "")),
                    "level": int(rule.get("level", 0)),
                    "count": 0,
                },
            )
            entry["count"] += 1
        return sorted(buckets.values(), key=lambda item: (-item["count"], item["rule_id"]))

    def export_laporan(
        self,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 100,
    ) -> str:
        self._audit("export_laporan", {"date_from": date_from, "date_to": date_to, "limit": limit})
        alerts = [_redact(alert, self.salt) for alert in self._filtered(date_from, date_to)][:limit]
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "date_from": date_from,
            "date_to": date_to,
            "count": len(alerts),
            "alerts": alerts,
        }
        return json.dumps(report, indent=2, ensure_ascii=False)


def build_mcp(client: WazuhReadOnly):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("ojs-wazuh-readonly")

    @mcp.tool()
    def rekap_harian(date_from: str | None = None, date_to: str | None = None, severity_min: int = 0):
        """Rekap alert OJS per tanggal, rule, dan severity."""
        return client.rekap_harian(date_from, date_to, severity_min)

    @mcp.tool()
    def top_ip_mencurigakan(limit: int = 10, date_from: str | None = None, date_to: str | None = None):
        """Top sumber alert dalam bentuk hash dan prefiks /24."""
        return client.top_ip_mencurigakan(limit, date_from, date_to)

    @mcp.tool()
    def cari_pola_serangan(
        pola: str,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
    ):
        """Cari alert berdasarkan pola, rule group, atau URL."""
        return client.cari_pola_serangan(pola, date_from, date_to, limit)

    @mcp.tool()
    def telusur_ip(ip: str, date_from: str | None = None, date_to: str | None = None):
        """Telusuri timeline alert untuk satu IP; output selalu dimasking."""
        return client.telusur_ip(ip, date_from, date_to)

    @mcp.tool()
    def korelasi_cve_ojs(
        cve: str,
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 50,
    ):
        """Petakan alert OJS ke CVE atau rule group terkait."""
        return client.korelasi_cve_ojs(cve, date_from, date_to, limit)

    @mcp.tool()
    def detail_alert(alert_id: str):
        """Ambil detail satu alert dengan bukti teredaksi."""
        return client.detail_alert(alert_id)

    @mcp.tool()
    def statistik_rule(date_from: str | None = None, date_to: str | None = None):
        """Hitung jumlah alert per rule dan level."""
        return client.statistik_rule(date_from, date_to)

    @mcp.tool()
    def export_laporan(
        date_from: str | None = None,
        date_to: str | None = None,
        limit: int = 100,
    ):
        """Ekspor laporan JSON teredaksi; tidak menulis file."""
        return client.export_laporan(date_from, date_to, limit)

    return mcp


def main() -> None:
    client = WazuhReadOnly.from_env()
    mcp = build_mcp(client)
    mcp.run()


if __name__ == "__main__":
    main()
