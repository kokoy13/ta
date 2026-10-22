#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_RULES="$SCRIPT_DIR/local_rules.xml"
SAMPLE_LOG="$SCRIPT_DIR/sample-ojs.log"
TARGET_RULES="/var/ossec/etc/rules/local_rules.xml"
BACKUP_RULES="/var/ossec/etc/rules/local_rules.xml.st4.bak"
OUTPUT="$SCRIPT_DIR/hasil-st4.txt"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan dengan sudo: sudo bash $0"
  exit 1
fi

if [[ ! -x /var/ossec/bin/wazuh-logtest ]]; then
  echo "wazuh-logtest tidak ditemukan. Pastikan Wazuh Manager 4.14 sudah terpasang."
  exit 1
fi

if [[ ! -f "$SRC_RULES" || ! -f "$SAMPLE_LOG" ]]; then
  echo "File local_rules.xml atau sample-ojs.log tidak ditemukan."
  exit 1
fi

if [[ -f "$TARGET_RULES" ]]; then
  cp -a "$TARGET_RULES" "$BACKUP_RULES"
else
  : > "$TARGET_RULES"
fi

cp "$SRC_RULES" "$TARGET_RULES"
systemctl restart wazuh-manager
sleep 2

{
  echo "=== ST4: wazuh-logtest ==="
  echo "Tanggal: $(date -Is)"
  echo "Rules: $TARGET_RULES"
  echo "Sampel: $SAMPLE_LOG"
  echo
  cat "$SAMPLE_LOG" | /var/ossec/bin/wazuh-logtest
} | tee "$OUTPUT"

echo
echo "=== Ringkasan event-level ==="
for rule_id in 100101 100110 100111 100112 100120 100121; do
  if grep -q "id: '$rule_id'" "$OUTPUT"; then
    echo "OK   $rule_id"
  else
    echo "MISS $rule_id"
  fi
done

echo
echo "=== Ringkasan correlation ==="
echo "Rule 100102, 100113, dan 100130 hanya muncul jika sesi logtest"
echo "mempertahankan state antar-baris. Jika tidak muncul, jalankan replay"
echo "melalui Wazuh Agent dan periksa /var/ossec/logs/alerts/alerts.json."
echo
echo "Output lengkap: $OUTPUT"
