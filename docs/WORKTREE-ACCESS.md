# Provisioned worktree write access

A fleet child receives its own detached worktree. `Workspace.Access` derives two
narrow grants from the target node's worktree registry:

- Ordinary file tools and shell commands may write `.ouroboros/deliver/` within
  that recorded worktree. The directory must already exist and resolve to its
  exact canonical spelling. Nested `.git` and `.ouroboros` names remain protected.
- An operator-approved, one-command `workspace_write` escalation additionally
  permits writes to that worktree's recorded Git administration directory and
  the shared mirror's `objects/` directory. This permits detached `git add` and
  `git commit`. The mirror's configuration, hooks, refs and other worktrees stay
  read-only. The child's `.git` pointer stays read-only even during escalation.

The record must be provisioned on this node, reference the target-local mirror
for its repository identifier, and match the Git administration directory's
backlink and common directory. Session arguments and remote worktree metadata
cannot supply these grants. Older records without the captured `git_dir` do not
receive an exception. Symlinked delivery roots and mismatched records fail closed.
The runtime creates `.ouroboros/deliver` before admitting the child.

The sandbox policy and helper JSON carry an optional `write_exceptions` list;
ordinary workspaces retain their existing policy shape. The helper accepts at
most three existing canonical directories in workspace modes. An older helper
rejects the unknown field instead of silently dropping enforcement. Seatbelt
reopens these paths after its parent denials, then denies nested protected names.
Linux backends reopen exact bind mounts and retain nested protected binds; the
helper's Landlock grants cover the same paths. The preload filter handles new
protected names, resolves cwd and `*at` directory descriptors, and preserves its
policy through `execve`, `execvp`, and an `env -i` child.

Linux's existing preload limitation still applies: static binaries and direct
syscalls do not pass through its new-name checks. Existing protected paths are
also protected by mounts; the helper additionally applies Landlock and seccomp.
This change does not claim a new kernel-level name filter.

Provisioned shell commands start with `GIT_CONFIG_NOSYSTEM=1`,
`GIT_CONFIG_GLOBAL=/dev/null`, and `GIT_CONFIG_COUNT=0`. Operator-global hooks,
rerere, and maintenance configuration therefore do not unexpectedly demand
writes to the mirror or execute during a child's ordinary Git command. The
command may supply its own identity with `git -c user.name=… -c user.email=…`.

## Ubuntu user namespace admission

Ubuntu systems enforcing AppArmor's unprivileged user namespace restriction may
allow `unshare` but refuse the subsequent identity mapping or mount operation.
`ouro-sandbox doctor` tests those operations as well, reports `usable: false`,
and mentions AppArmor when setup fails. Run doctor as the actual daemon user:
root success does not prove that the daemon can use the helper.

For a reviewed installed helper, an administrator can grant user namespace
admission to its **exact executable path**. Adapt this profile to that path:

```text
abi <abi/5.0>,
include <tunables/global>
profile ouroboros-sandbox /absolute/install/priv/sandbox/ouro-sandbox flags=(unconfined) {
  userns,
}
```

Install it as a root-owned file in `/etc/apparmor.d/`, then load that file with
`sudo apparmor_parser -r /etc/apparmor.d/ouroboros-sandbox`. The profile grants
namespace admission; Ouroboros still applies its mount, Landlock, seccomp and
capability restrictions before executing the command. Use a reviewed installation
path, and update the profile when that path changes. Do not disable the machine's
user namespace restriction globally. Verify `doctor` and a real sandboxed write
and denial as the daemon user after installation.

## Validation evidence

The focused Mac suite covers native write permission and SafeWrite, real shell
logging to delivery, actual detached Git staging/commit after escalation, a
normal Git denial, symlink/registry rejection, and mirror/sibling write denials.

The Linux enforcement suite builds and loads this change's preload library and
runs the same delivery/commit/neighbor cases against the actual helper. On the
Ubuntu fleet validation host (kernel 7.0.0-28, Landlock ABI 8), all 31 kernel tests
passed as `ubuntu` after exact-path AppArmor admission; the global restriction
remained enabled. A separate bubblewrap run as `ubuntu` passed delivery logging,
ordinary Git denial, approved commit, seven neighboring fences, and nested-name,
case, and `env -i` denials. These are local-source and disposable-host validation,
not evidence of a published release.
