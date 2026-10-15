# Website sample run — 15 October 2026

The home page at [ukai.sh](https://ukai.sh/) shows one run of `ukai-jail` and
an excerpt of its receipt. This record holds that run's complete output, so
every line on the page can be checked against what the binary produced.

It is one demonstration run with the `tool` profile, not a benchmark,
an acceptance gate or a conformance claim.

## What ran

The [command](results/website-sample-run-2026-10-15/command.sh), exactly as the
page shows it, run in an empty scratch workspace:

```sh
ukai-jail run --profile tool --workspace . --limit wall=30s -- \
    sh -c "cat $HOME/.ssh/authorized_keys; curl -sS https://example.com; echo ok > result.txt"
```

The outer shell expands `$HOME` to `/home/ubuntu` before the jail starts, so
the command inside asks for a file that exists on the host. The
[terminal transcript](results/website-sample-run-2026-10-15/terminal.txt):

```text
cat: /home/ubuntu/.ssh/authorized_keys: No such file or directory
curl: (6) Could not resolve host: example.com
[exit status 0]
$ cat result.txt
ok
```

- **The SSH file:** the `tool` profile does not mount the home directory, so
  the path does not exist inside the sandbox. Nothing was denied: the
  receipt's `fs.deny` class is active with 0 events.
- **The network:** the run had no network (`applied.network.mode` is `none`,
  through a network namespace). The journal records `curl`'s two connection
  attempts and its exit status 6.
- **The write:** `result.txt` was created in the workspace (`fs.write`, 1 event)
  and remains there after the run.
- **The exit:** `sh` exited 0 because its last command succeeded; the earlier
  failures do not change the shell's status.

## Where and how

From [host.txt](results/website-sample-run-2026-10-15/host.txt):

| Fact | Value |
| --- | --- |
| Host | The Linux reference host: Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86_64 |
| Backend | bubblewrap 0.11.1 |
| Account | `ubuntu`, non-root; no sudo used |
| Source | A clean clone of `https://github.com/monocursive/ukai` at `cd476ba7cf499cc27e1de1e8e559281b6d5e6cd2` |
| Build | `cargo build --release --locked -p ukai-jail` with `UKAI_BUILD_REVISION` set to that commit and `UKAI_BUILD_DIRTY=false`, checked against git by the build |
| Build inputs | `sha256:54c52eb2ba638d434ded066893c6d03388b1c822866143ca335e3f14de8313a2` ([version.json](results/website-sample-run-2026-10-15/version.json)) |
| Binary | `sha256:43265c4a715b8c66e2925a5d5886ecf10298896b389045d65e9e8ba7e99f16ae` |
| State | `UKAI_CONFIG_DIR` and `UKAI_DATA_DIR` set to private scratch directories |

[doctor.json](results/website-sample-run-2026-10-15/doctor.json) is
`ukai-jail doctor --profile tool --json` from the same binary, run just before;
it reports `ready: true`.

## The files

| File | What it is |
| --- | --- |
| [command.sh](results/website-sample-run-2026-10-15/command.sh) | The command as run |
| [terminal.txt](results/website-sample-run-2026-10-15/terminal.txt) | Its combined output, exit status and the written file |
| [jail.json](results/website-sample-run-2026-10-15/jail.json) | The final receipt, attempt `att_ac6f7137-b248-40a1-92b7-b1c109161c8b` |
| [policy.json](results/website-sample-run-2026-10-15/policy.json) | The resolved policy |
| [trace.ndjson](results/website-sample-run-2026-10-15/trace.ndjson) | The event journal |
| [tail.txt](results/website-sample-run-2026-10-15/tail.txt) | `ukai-jail tail` for the attempt |
| [version.json](results/website-sample-run-2026-10-15/version.json), [doctor.json](results/website-sample-run-2026-10-15/doctor.json), [host.txt](results/website-sample-run-2026-10-15/host.txt) | Build and host facts |
| [SHA256SUMS](results/website-sample-run-2026-10-15/SHA256SUMS) | Hashes of every file above |

`jail.json`, `policy.json`, `trace.ndjson`, `tail.txt`, `version.json` and
`doctor.json` are the binary's output, unedited; they keep the host paths they
observed. `host.txt` and `command.sh` were written by the capture script.

## What the page shows

The page's terminal is `terminal.txt` without the exit-status line. Its
receipt is an excerpt of `jail.json`: every value shown is the file's value,
and `…` marks omitted fields. The page's three questions map to the
receipt's `applied`, `outcome` with `lifetime`, and `coverage`.

## Reproduce

On a Linux host where `ukai-jail doctor --profile tool` reports ready, from an
empty directory:

```sh
ukai-jail run --profile tool --workspace . --limit wall=30s -- \
    sh -c "cat $HOME/.ssh/authorized_keys; curl -sS https://example.com; echo ok > result.txt"
cat result.txt
ukai-jail tail
```

Attempt ids, process ids, timestamps and digests differ on every run.
