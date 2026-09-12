# Linux bubblewrap: Ubuntu user-namespace policy

Installing `bubblewrap` does not establish usable sandboxing. On Ubuntu 24.04,
AppArmor can allow unprivileged user-namespace creation while denying capabilities
inside it. A normal shell may show `unconfined` and still transition to the
`unprivileged_userns` profile when bubblewrap starts.

In a bounded Ubuntu 24.04.5 ARM64 guest, the loopback `RTM_NEWADDR` failure matched
kernel AppArmor denials for `setpcap` and `net_admin`. Enabling the exact distro
profile below restored both the original probe and the actual packaged Ouroboros
shell path; removing it restored the refusal. This established a deployment-policy
prerequisite, not a product implementation defect. No rebuild or code fix was needed.

**This is an opt-in administrator policy decision, not a universal installation
step.** The extra profile is experimental/unsupported and disabled by default.
It attaches to `/usr/bin/bwrap` for all users and applications using that path,
not just Ouroboros. If existing policy deliberately refuses this use, stop or use
an administrator-approved environment. Do not disable AppArmor/global restrictions,
add file capabilities or setuid to bwrap, run bwrap/the agent as root, add custom
broad capability allowances, or silently select unrestricted execution.

## 1. Check before building or starting a runtime

Run in an ordinary terminal as the same non-root user who will run Ouroboros,
outside any already-contained agent shell. These diagnostics do not change policy:

```sh
id
uname -r -m
command -v bwrap
bwrap --version
dpkg-query -W bubblewrap apparmor
cat /proc/self/attr/current
/usr/sbin/sysctl kernel.apparmor_restrict_unprivileged_userns \
  kernel.unprivileged_userns_clone user.max_user_namespaces
date --iso-8601=ns
if bwrap --ro-bind / / --unshare-net --dev /dev --proc /proc -- /bin/true; then
  printf 'probe_exit=0\n'
else
  printf 'probe_exit=%s\n' "$?"
fi
```

If bwrap is missing, arrange the normal distro `bubblewrap` prerequisite with the
administrator first. If the probe succeeds, **do not apply this correction just
because you use Ubuntu**; continue to actual product verification. A version
string or this small probe alone is not proof of product containment.

For a failure, the administrator can read matching recent kernel records:

```sh
sudo journalctl -k --since '2 minutes ago' --no-pager -o short-iso \
  | grep -E 'apparmor|bwrap|DENIED|userns'
```

The diagnosed signature was `bwrap: loopback: Failed RTM_NEWADDR: Operation not
permitted`, followed at the same time by `userns_create` transitioning bwrap from
`unconfined` to `unprivileged_userns` and capability denials for `setpcap` and
`net_admin`. Retain the probe exit, package/kernel versions and matching audit
records. **The errno alone does not establish this cause.** Missing audit access,
other errors, containers, different executable paths or different policy require
their own diagnosis, not blindly applying this recipe. Review/redact logs before
sharing; no upload is required.

## 2. Obtain and review the distro profile without installing other profiles

Tested combination: Ubuntu 24.04.5, Linux 6.8.0-139, ARM64, bubblewrap
`0.9.0-1ubuntu0.1`, AppArmor and `apparmor-profiles`
`4.0.1really4.0.1-0ubuntu0.24.04.7`. The profile comes from Ubuntu's
`noble-updates/main` **apparmor-profiles** package, architecture `all`; the ARM64
test obtained it through the normal Ubuntu ports repository. Use your configured
official Ubuntu repositories and authenticated APT metadata, not a copied private
test file or an arbitrary downloaded profile. The installed `apparmor` package
supplies `/usr/sbin/apparmor_parser`, ABI files and tunables used below.

In the same ordinary shell, download and extract only this small package. This
does **not** install `apparmor-profiles` or activate its other profiles:

```sh
profile_work=$(mktemp -d "$HOME/ouro-bwrap-profile.XXXXXX")
(
  set -eu
  : "${profile_work:?Directory creation failed; stop here}"
  test -d "$profile_work"
  cd "$profile_work"
  apt-cache policy apparmor-profiles
  apt-get download apparmor-profiles=4.0.1really4.0.1-0ubuntu0.24.04.7
  deb=apparmor-profiles_4.0.1really4.0.1-0ubuntu0.24.04.7_all.deb
  printf '%s  %s\n' \
    bdac5b74d884643653565c52ed7483c9582e646ff72cce8d95d0eb8467a3139c \
    "$deb" | sha256sum -c -
  dpkg-deb -x "$deb" unpacked
  src=unpacked/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
  printf '%s  %s\n' \
    11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9 \
    "$src" | sha256sum -c -
  cat unpacked/usr/share/apparmor/extra-profiles/README
  cat "$src"
  printf 'Retain this review/rollback directory: %s\n' "$profile_work"
)
```

Stop on any failure. If this exact version is no longer available, do not use
unauthenticated APT options or skip the checksum. A newer distro profile needs its
own review and validation; these digests bind the tested bytes, not every update.
No package downgrade or repository reconfiguration is prescribed here.

Read the entire profile and its README with the administrator. Ubuntu explicitly
calls these extra profiles unsupported and warns they may break default or local
configurations. The `bwrap` setup profile has broad AppArmor allowances, including
`allow capability`, so it can set up namespaces. This does not add Linux file
capabilities. Executed children are stacked with `unpriv_bwrap`, which has
`audit deny capability`. Neither the parent allowance nor package provenance is a
production compatibility guarantee. Review the conditional local includes too;
the guest was reported stock, but its receipts did not separately inventory those
local-include paths. The explicit local-file checks below are an added precondition,
not a measured historical absence claim.

## 3. Administrator-approved activation

Only proceed after approval for **this machine** and coordination with other bwrap
users. Keep the reviewed package/directory for rollback. This recipe requires the
destination and both profile names to be absent; it must not replace an existing
administrator policy. Check for existing policy and local overrides first:

```sh
sudo grep -E '^(bwrap|unpriv_bwrap|unprivileged_userns) ' \
  /sys/kernel/security/apparmor/profiles
sudo ls -ld /etc/apparmor.d/bwrap-userns-restrict \
  /etc/apparmor.d/local/bwrap-userns-restrict /etc/apparmor.d/local/unpriv_bwrap
```

For the tested starting state, only `unprivileged_userns (enforce)` was loaded and
the destination profile file was absent. For this recipe, require all three named
files absent (`ls` reports that absence). If either bwrap profile
is already loaded, an override/file exists, AppArmor is not enforcing, or policy
differs, stop and have the administrator reconcile it rather than overwrite it.
The global restriction must remain `1`; do not change it to fit this recipe.

After review, in the same shell retaining `profile_work`:

```sh
(
  set -eu
  src="${profile_work:?}/unpacked/usr/share/apparmor/extra-profiles/bwrap-userns-restrict"
  dst=/etc/apparmor.d/bwrap-userns-restrict
  printf '%s  %s\n' \
    11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9 \
    "$src" | sha256sum -c -
  test "$(/usr/sbin/sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
  sudo test ! -e "$dst"
  sudo test ! -L "$dst"
  sudo install -o root -g root -m 644 "$src" "$dst"
  sudo /usr/sbin/apparmor_parser -r "$dst"
  sha256sum "$dst"
  sudo grep -E '^(bwrap|unpriv_bwrap|unprivileged_userns) ' \
    /sys/kernel/security/apparmor/profiles
  /usr/sbin/sysctl kernel.apparmor_restrict_unprivileged_userns \
    kernel.unprivileged_userns_clone
)
```

Require the same installed profile hash, `bwrap`, `unpriv_bwrap` and
`unprivileged_userns` all in **enforce** mode, and both displayed sysctls still `1`
as in the recorded baseline. A parser error is not success; retain the error and
have the administrator reconcile/remove only the introduced policy. Do not use
complain mode or restart AppArmor globally to hide a failure.

## 4. Verify the setup and the actual product separately

Re-run the exact non-root stock probe from section 1: expected `probe_exit=0`.
Check that unrelated unprofiled namespace setup remains restricted:

```sh
if unshare --user --map-root-user --net /bin/true; then
  printf 'UNEXPECTED: unprofiled namespace setup succeeded\n'
else
  printf 'unprofiled_unshare_exit=%s\n' "$?"
fi
/usr/sbin/sysctl kernel.apparmor_restrict_unprivileged_userns \
  kernel.unprivileged_userns_clone
sudo journalctl -k --since '2 minutes ago' --no-pager -o short-iso \
  | grep -E 'apparmor|unshare|unpriv'
```

The guest got exit `1` with a matching `unprivileged_userns` `sys_admin` denial;
the global values stayed `1`. Unexpected success or missing/different policy
evidence is not a pass. Stop qualification and ask the administrator to reconcile.

**Ouroboros caches backend detection per runtime node, not per session.** If an
already-running runtime detected the old policy, opening a new session does not
refresh it. After approved setup, stop/start only an **operator-owned idle**
standalone runtime using `ouro stop` / `ouro daemon` in its exact original
environment/data directory, as described in [PREVIEW.md](PREVIEW.md#one-useful-first-journey).
Never restart a shared/protected runtime or delete its state. A fresh owned runtime
will probe the new policy. No restart is necessary when no runtime has started yet.

### Reproducible manual product check

This uses the normal client and requires ordinary model access; it is not the
no-model release-eval harness used for the recorded ARM64 proof. Put your native
`ouro` binary on `PATH` first. In an ordinary terminal, create only new synthetic
state (keep this shell for the variables and function below):

```sh
test_root=$(mktemp -d "$HOME/ouro-bwrap-check.XXXXXX")
ouro_bin=$(command -v ouro)
(
  set -eu
  : "${test_root:?Directory creation failed}"
  : "${ouro_bin:?Put the native ouro binary on PATH first}"
  test -x "$ouro_bin"
  umask 077
  mkdir -p "$test_root/workspace/.git" "$test_root/workspace/.ouroboros" \
    "$test_root/home" "$test_root/config" "$test_root/data" "$test_root/cache"
  for file in outside workspace/.git/protected workspace/.ouroboros/retained \
    data/synthetic-control; do
    printf unchanged > "$test_root/$file"
  done
  printf '# unchanged\n' > "$test_root/workspace/ouroboros.toml"
  printf 'Owned check directory: %s\n' "$test_root"
)
```

Stop if setup fails. The `.git` here is only a synthetic protected directory, not
real repository metadata. Do not substitute a working repository or existing data
directory. Start an isolated, non-distributed runtime using this shell function;
no account state or inherited cluster/release flags are copied:

```sh
check_ouro() (
  cd "${test_root:?}/workspace" || exit 1
  env -i HOME="$test_root/home" XDG_CONFIG_HOME="$test_root/config" \
    XDG_DATA_HOME="$test_root/data" XDG_CACHE_HOME="$test_root/cache" \
    OUROBOROS_DATA_DIR="$test_root/data" OUROBOROS_DIST=none \
    PATH="$PATH" SHELL=/bin/sh LANG=C.UTF-8 "${ouro_bin:?}" "$@"
)
check_ouro web
```

The printed browser URL is a credential: keep it private. Use ordinary sign-in,
not copied authentication files. Use the selected `workspace` directory and
interactive approval. Ask for the following commands through the **Bash tool**,
not the file tools; run each command separately and record its result. The normal
terminal client (`check_ouro` with no arguments) is also usable; leave that client
before using this ordinary terminal for external checks, without deleting sessions.

1. In a `read_only` session, `cat /etc/os-release` must succeed and
   `printf forbidden > denied.txt` must fail.
2. In a `workspace_write` session, `printf allowed > allowed.txt` must succeed.
   Each of these must fail without changing its target:

   ```sh
   printf changed > ../outside
   printf changed > .git/protected
   printf changed > .ouroboros/retained
   printf changed > ouroboros.toml
   printf changed > ../data/synthetic-control
   ```

3. In that contained Bash session, run:

   ```sh
   cat /proc/self/attr/current
   grep -E '^(CapEff|CapPrm|CapBnd|NoNewPrivs):' /proc/self/status
   readlink /proc/self/ns/net
   unshare --user --map-root-user --net /bin/true
   ```

   Expect `bwrap//&unpriv_bwrap (enforce)`, CapPrm/CapEff/CapBnd all zero and
   `NoNewPrivs: 1`; the final `unshare` must fail. The guest recorded an
   `unpriv_bwrap` `sys_admin` denial. Compare the namespace with the ordinary
   terminal's `readlink /proc/self/ns/net`: they must differ.

Independently check the actual files in the ordinary terminal, not merely a
model's summary or denial annotation:

```sh
readlink /proc/self/ns/net
(
  set -eu
  test ! -e "${test_root:?}/workspace/denied.txt"
  test "$(cat "$test_root/workspace/allowed.txt")" = allowed
  for file in outside workspace/.git/protected workspace/.ouroboros/retained \
    data/synthetic-control; do
    test "$(cat "$test_root/$file")" = unchanged
  done
  printf '# unchanged\n' | cmp - "$test_root/workspace/ouroboros.toml"
  printf 'Synthetic file controls passed\n'
)
```

For the network control, Python 3 is an additional **check-only** prerequisite.
In the ordinary terminal start this owned listener, which uses a random loopback
port, proves an ordinary connection works, then waits at most 120 seconds. It
closes its own socket and exits without a signal or persistent server:

```sh
python3 - "$test_root/workspace/listener-port" <<'PY' &
import pathlib, socket, sys
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    with socket.create_connection(('127.0.0.1', port), timeout=2):
        client, _ = listener.accept()
        client.close()
    pathlib.Path(sys.argv[1]).write_text(str(port))
    listener.settimeout(120)
    print('READY: ordinary positive control connected; run contained check now', flush=True)
    try:
        client, _ = listener.accept()
    except socket.timeout:
        print('Listener received no further connection', flush=True)
    else:
        client.close()
        raise SystemExit('UNEXPECTED: listener received another connection')
PY
listener_pid=$!
```

After `READY`, **while that listener is still waiting**, ask contained Bash to run
this exact command from the workspace; it reads only the synthetic port file:

```sh
python3 -c 'import pathlib,socket; p=int(pathlib.Path("listener-port").read_text()); s=socket.create_connection(("127.0.0.1",p),timeout=2); s.close()'
```

Require a connection failure, then in the ordinary terminal `wait "$listener_pid"`
for the no-further-connection message and exit `0`. An unexpected connection,
listener error, missing Python, or an attempt made after the listener expired is
not a pass. Retain both results; a dead endpoint alone proves nothing. The listener
finishes within 120 seconds even if the UI task never runs; report that case as
incomplete rather than retrying blindly.

Do not approve a wider-posture retry to make a negative control succeed. When the
owned sessions are idle and the listener has exited, `check_ouro stop` stops only
this isolated runtime. Keep the new directory for local reconciliation; do not
upload it (it can now contain auth/session state) or remove other directories.
These targeted checks do not replace the
[useful authenticated task and recovery journey](PREVIEW.md#one-useful-first-journey).

## 5. Roll back only the introduced profile

Coordinate rollback with other users of `/usr/bin/bwrap`; quiesce only runtimes
you own. The following applies **only if section 3 introduced the previously
absent file and profiles and nobody has changed them since**. If they changed,
stop for administrator reconciliation; do not delete someone else's policy.

```sh
(
  set -eu
  dst=/etc/apparmor.d/bwrap-userns-restrict
  sudo test ! -L "$dst"
  printf '%s  %s\n' \
    11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9 \
    "$dst" | sha256sum -c -
  sudo /usr/sbin/apparmor_parser -R "$dst"
  sudo rm -- "$dst"
  sudo grep -E '^(bwrap|unpriv_bwrap|unprivileged_userns) ' \
    /sys/kernel/security/apparmor/profiles
  /usr/sbin/sysctl kernel.apparmor_restrict_unprivileged_userns \
    kernel.unprivileged_userns_clone
)
```

Require only `unprivileged_userns (enforce)` remaining from those three names and
unchanged global values. Repeat section 1's probe and audit check: the guest
returned exit `1`, the original loopback error and the original capability denials.
No global sysctl, package, unrelated profile or runtime state is removed. Refresh
detection only in a fresh or owned idle runtime before any later product check;
a cached success is not proof after rollback either. Keep the small package and
review record until reconciliation is complete.

## Evidence boundary

The public shell blocks are administrator-oriented adaptations of the recorded
operations, **not a verbatim end-to-end executed transcript**. The guest downloaded
the repository's selected candidate version and printed its hashes; the public
exact-version selector, unique review directory, checksum assertions, symlink and
local-file preconditions, and failure-handling wrappers are added safeguards.
The complete blocks have not been executed end to end here. Syntax checks passed;
a small harmless-stub check separately verified acquisition success and failure
status propagation (directory creation, download and both checksum failures),
without downloads or policy commands. The tested guest operations were extraction
of the identified package, installation of the unchanged profile, parser `-r`,
stock/product controls, parser `-R` and removal of only the introduced file.
The concrete public interactive examples and owned-runtime restart remain
instructions for validation on the intended installation, not captured UI results.

On 2026-09-12, one Ubuntu 24.04.5 ARM64 HVF guest exercised the original probe,
activation, actual packaged `Tools.Bash` through Sandbox/Exec/bwrap as a non-root
user, file/network/child-capability controls, unrelated-userns denial and rollback.
The runtime evaluations used fresh BEAM release-eval VMs per phase within that
same ARM64 guest (not cached detection), no model and no recompile. The older
binary SHA-256 was
`4841e6fbed1e1feda4abf625b4dc1d0cfc08d315793d40ad8de7637a80d91986`;
[PREVIEW.md](PREVIEW.md#candidate-notes-2026-09-12-after-platform-runs-and-disk-cleanup)
records its selected-source attribution. Actual guest exit `0` was recorded.

This is not x86-64 remedy proof, current-HEAD binary qualification, full Linux
auth/task/check/recovery/authenticated-browser acceptance, or a promise for other
Ubuntu/package/kernel combinations. No reboot-persistence test was performed.
The shell still has the [documented OS-sandbox limits](ARCHITECTURE.md#safety-boundaries),
including no Linux seccomp filter and limitations for newly created nested protected
directories. Tested pre-existing protected paths do not remove those limits.
