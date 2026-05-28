#!/bin/bash

echo "[TEST] Début simulation comportement suspect"

echo "Fichier créé par la sandbox" > /tmp/sandbox_created_file.txt

mkdir -p /tmp/sandbox_test_dir
echo "test modification" > /tmp/sandbox_test_dir/modified.txt

whoami
hostname
ps aux | head
ss -tunap 2>/dev/null | head

echo "[TEST] Fin simulation"