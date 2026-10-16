#!/bin/bash
# Kernel syscall sweep vs the jail's ground-truth deny table.
# Usage: sysnum_sweep.sh <ukai-jail-binary> <outdir>
set -u
JAIL=${1:?ukai-jail path}
OUT=${2:?outdir}
mkdir -p "$OUT"

# 1) Ground truth from the binary itself (hidden subcommand).
"$JAIL" __seccomp-table --json > "$OUT/seccomp_table.json" 2> "$OUT/seccomp_table.err" || true

# 2) Every syscall number the running kernel knows (x86_64 + x32).
python3 - "$OUT/kernel_syscalls.txt" <<'PY'
import re, sys
nums = {}
try:
    with open('/usr/include/x86_64-linux-gnu/asm/unistd_64.h') as f:
        for line in f:
            m = re.match(r'#define __NR_(\w+)\s+(\d+)', line)
            if m: nums[int(m.group(2))] = m.group(1)
    with open('/usr/include/x86_64-linux-gnu/asm/unistd_32.h') as f:
        for line in f:
            m = re.match(r'#define __NR_(\w+)\s+(\d+)', line)
            if m: nums.setdefault(int(m.group(2)) + 0x40000000, 'i386:' + m.group(1))
except FileNotFoundError:
    pass
try:
    with open('/usr/include/x86_64-linux-gnu/asm/unistd_x32.h') as f:
        for line in f:
            m = re.match(r'#define __NR_(\w+)\s+(\d+)', line)
            if m: nums.setdefault(int(m.group(2)) | 0x40000000, 'x32:' + m.group(1))
except FileNotFoundError:
    pass
for n in sorted(nums):
    print(f"{n}\t{nums[n]}")
PY
wc -l "$OUT/kernel_syscalls.txt"
