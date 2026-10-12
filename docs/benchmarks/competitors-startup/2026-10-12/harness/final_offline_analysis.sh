#!/bin/sh
set -eu
bench_root=docs/benchmarks/competitors-startup/2026-10-12
python3 "$bench_root/harness/select_startup.py" "$bench_root/results"
python3 "$bench_root/harness/compare_paired.py" "$bench_root/results" --out "$bench_root/analysis/paired"
python3 "$bench_root/harness/verify_startup.py" "$bench_root"
python3 "$bench_root/harness/finalize_saved_evidence.py" "$bench_root"
python3 "$bench_root/harness/verify_frozen_inputs.py" "$bench_root"
python3 "$bench_root/harness/compare_history.py" "$bench_root"
python3 "$bench_root/harness/render_performance_tables.py" "$bench_root"
python3 "$bench_root/harness/build_startup_report.py" "$bench_root"
python3 "$bench_root/harness/audit_results.py" "$bench_root/results" --out "$bench_root/analysis/all-retained-datasets.json"
