# Pi write investigation

The slow path is closing files that were just truncated on the Pi's ext4 SD
storage. It also occurs in the direct and MXC controls. It is not established as
an Ouro-specific write regression.

The original scored payload opens 1,000 files with O_WRONLY | O_CREAT | O_TRUNC,
writes 1,024 bytes to each, then closes each file. It does not call fsync. Earlier
runs repeatedly reuse the output paths, so almost every measurement truncates
existing files. That behavior is retained in this rerun.

An excluded, instrumented payload separates open, write and close time. A second
excluded matrix uses six seeded rounds of identical 1,000-write work per cell,
with ordinary direct execution and the previous strictly observed Ouro binary.
Each truncate/overwrite cell starts with identical existing contents; each fresh
cell starts with an empty output directory. The [raw matrix](candidates/v3/results/pi/write-matrix/matrix.json)
and [machine-readable summary](analysis/pi-write-matrix.csv) preserve every cell.

| Direct variant | Median total (ms) | Open (ms) | Write (ms) | Close (ms) |
|---|---:|---:|---:|---:|
| Truncate existing | 852.2 | 28.5 | 12.8 | 804.7 |
| Overwrite existing, without truncation | 14.8 | 4.0 | 6.4 | 1.6 |
| Create fresh | 62.4 | 43.3 | 13.8 | 2.1 |

Operation columns are separate medians and need not sum to the median total.
The old observed truncate cells remain variable (close median 420.9 ms), whereas
observed overwrite/fresh close medians are 2.2/2.6 ms. Observation adds real work:
its median totals for overwrite/fresh are 406.6/451.2 ms, versus direct
14.8/62.4 ms. The inexpensive storage variants do not remove ptrace overhead.

Two direct straces reproduce the distinction: first fresh-file close total
about 18.9 ms, subsequent truncating close total about 618.6 ms. Host samples
show ample available memory and slow closes even at 1.5 GHz; no throttling was
reported. Frequency scaling and SD writeback still contribute variation, and
these observations do not prove they have zero effect.

The leading explanation is ext4's default auto_da_alloc handling. The
[ext4 documentation](https://docs.kernel.org/admin-guide/ext4.html) describes its
protection for truncate-and-rewrite patterns. In upstream Linux 6.18,
[ext4_truncate and ext4_alloc_da_blocks](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/ext4/inode.c)
mark zero-length truncation for delayed allocation on close and map/start dirty
page writeback; [ext4_release_file](https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/ext4/file.c)
calls that path when the close flag is set. This fits the measured hotspot and
semantics controls. It remains an inference: these upstream sources share the
Pi kernel's major version, but no stack trace proves the exact Raspberry Pi
kernel path, nor was allocation/writeback isolated from all scheduling effects.

No filesystem options, dirty-page knobs, CPU governor, durability requirements,
storage paths or observer settings were changed. The overwrite/fresh variants
are diagnostic evidence with different semantics, never substituted for the
original scored workload. The final matched old/new score and confidence interval
are reported in README.md; the after diagnostic uses the withdrawn v3 candidate and is retained separately. Its
version-query optimization was removed for the final score. It repeats the direct
close hotspot (822.0 ms truncating, 1.6/2.1 ms overwrite/fresh); observed closes
remain variable. Final write timings use the final binary and original workload.

The final matched v5 score and paired confidence interval are reported in
[README.md](README.md). No payload I/O path, mount option or writeback setting
changed, and the observed close timings remain variable. Timing and
writeback/pacing interactions can exceed the startup reduction. Repeatability
beyond this cohort is unproven; there is no general SD throughput or durability
claim. Superseded v4/v5 write measurements remain in candidate evidence.

Final v6 write wall medians are 672.3 ms before and 501.2 ms after. The paired
median change interval is [-593.5,27.0] ms, crossing zero; no reliable general
write-throughput improvement is established. The matched startup improvement
is clearer. The final Pi Git preflight refuses after the existing five-second
receipt-persistence budget, and the earlier excluded v5 cohort has a baseline
CPU preflight persistence refusal. Both are retained availability failures; no
causal connection to the ext4 close hotspot was demonstrated, and the budget
was not increased.

One final detached-root canary reports entry_abandoned/evidence_lost while its
receipt verifies an empty tree; its heartbeat result is inconclusive. The
separate unchanged-settings 30-pair lifetime diagnostic is successful for both
binaries, with all heartbeats witnessed/stopped, empty trees and no gaps. The
original failed/inconclusive result remains in the benchmark, not replaced by
these diagnostics. See analysis/pi-lifetime-diagnostic.json.
