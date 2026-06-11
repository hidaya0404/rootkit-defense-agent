#!/bin/bash

set -u

ARTIFACT_PATH="$1"
RESULT_DIR="$2"

mkdir -p "$RESULT_DIR"

echo "[+] Début analyse sandbox"
echo "[+] Artefact : $ARTIFACT_PATH"
echo "[+] Dossier résultats : $RESULT_DIR"

date -Iseconds > "$RESULT_DIR/timestamp_start.txt"

echo "[+] Baseline processus avant exécution"
ps aux > "$RESULT_DIR/processes_before.txt"

echo "[+] Baseline réseau avant exécution"
ss -tunap > "$RESULT_DIR/network_before.txt" 2>/dev/null

echo "[+] Baseline fichiers /tmp avant exécution"
find /tmp -type f -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n" > "$RESULT_DIR/files_tmp_before.txt" 2>/dev/null

echo "[+] Exécution contrôlée avec timeout"
chmod +x "$ARTIFACT_PATH"

timeout 8s strace -f -o "$RESULT_DIR/strace.log" "$ARTIFACT_PATH" \
  > "$RESULT_DIR/stdout.log" \
  2> "$RESULT_DIR/stderr.log"

EXIT_CODE=$?
echo "$EXIT_CODE" > "$RESULT_DIR/exit_code.txt"

echo "[+] Collecte après exécution"
ps aux > "$RESULT_DIR/processes_after.txt"
ss -tunap > "$RESULT_DIR/network_after.txt" 2>/dev/null
find /tmp -type f -printf "%p %s %TY-%Tm-%Td %TH:%TM:%TS\n" > "$RESULT_DIR/files_tmp_after.txt" 2>/dev/null

date -Iseconds > "$RESULT_DIR/timestamp_end.txt"

echo "[+] Analyse terminée"
