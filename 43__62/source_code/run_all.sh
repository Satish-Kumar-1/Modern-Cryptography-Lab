#!/usr/bin/env bash
set -euo pipefail
mkdir -p logs
for f in exp1_normal_exchange exp2_mitm_attack exp3_authenticated_exchange exp4_tamper_test exp5_hkdf_analysis exp6_error_handling; do
  echo "Running $f"
  python3 "$f.py" | tee "logs/$f.txt"
done
echo "All six experiments completed. Logs are in logs/."
