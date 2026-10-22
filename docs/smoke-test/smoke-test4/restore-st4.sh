#!/usr/bin/env bash
set -euo pipefail

TARGET_RULES="/var/ossec/etc/rules/local_rules.xml"
BACKUP_RULES="/var/ossec/etc/rules/local_rules.xml.st4.bak"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan dengan sudo: sudo bash $0"
  exit 1
fi

if [[ -f "$BACKUP_RULES" ]]; then
  cp -a "$BACKUP_RULES" "$TARGET_RULES"
  systemctl restart wazuh-manager
  echo "local_rules.xml dikembalikan dari backup."
else
  echo "Backup tidak ditemukan. Periksa $TARGET_RULES secara manual."
  exit 1
fi
