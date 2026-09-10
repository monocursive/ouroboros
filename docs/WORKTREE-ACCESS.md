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

The sandbox policy carries an optional `write_exceptions` list of at most three
existing canonical directories, and only in workspace modes; ordinary workspaces
retain their existing policy shape. Seatbelt reopens these paths after its parent
denials, then denies nested protected names. bubblewrap reopens exact bind mounts
and retains nested protected binds.

A protected *name* created after the command starts, **below the top level of a
writable root**, is not denied on Linux. It used to be, by an `LD_PRELOAD` filter
that resolved cwd and `*at` directory descriptors and survived `execve`, `execvp`
and an `env -i` child — and that a static binary or a direct syscall walked past
anyway. The filter and the `ouro-sandbox` backend that also loaded it were deleted
by docs/proposals/core.md §4 A2. A writable root's *own* `.git` or `.ouroboros` is
still covered whether or not it is there: bound read-only over itself when it
exists, and covered by a read-only bind of the command's empty scratch directory
when it does not. Protection on Linux is mounts, and a mount can only name a
destination known before the namespace is built; Seatbelt still denies every case
by regex.

Provisioned shell commands start with `GIT_CONFIG_NOSYSTEM=1`,
`GIT_CONFIG_GLOBAL=/dev/null`, and `GIT_CONFIG_COUNT=0`. Operator-global hooks,
rerere, and maintenance configuration therefore do not unexpectedly demand
writes to the mirror or execute during a child's ordinary Git command. The
command may supply its own identity with `git -c user.name=… -c user.email=…`.

## Ubuntu user namespace admission

Ubuntu systems enforcing AppArmor's unprivileged user namespace restriction may
allow `unshare` but refuse the subsequent identity mapping or mount operation.
`Bwrap.probe/1` runs a representative read-only mount and a second command that
unshares the network namespace before the backend is selected at all, so such a
host reports no usable backend rather than wrapping nothing. Run the runtime as
the actual daemon user when checking: root success does not prove that the daemon
can enter a namespace.

The host-wide switch is `kernel.apparmor_restrict_unprivileged_userns`; CI's
ubuntu-24.04 job sets it to 0 for the runner, and `scripts/wasm-linux-test.sh`
writes it inside its container when it can. An administrator who does not want to
lift it machine-wide can grant namespace admission to `bwrap`'s exact executable
path with an AppArmor profile carrying `userns,`. Ouroboros still applies its
mounts and its network namespace before executing the command. Verify a real
sandboxed write and denial as the daemon user after any such change.

## Validation evidence

The focused Mac suite covers native write permission and SafeWrite, real shell
logging to delivery, actual detached Git staging/commit after escalation, a
normal Git denial, symlink/registry rejection, and mirror/sibling write denials.

The Linux evidence is the bubblewrap run: on the Ubuntu fleet validation host
(kernel 7.0.0-28) as `ubuntu`, delivery logging, ordinary Git denial, approved
commit and seven neighboring fences all passed. The half of the nested-name, case
and `env -i` denials in that run that covered a name *created* by the command came
from the `LD_PRELOAD` filter and is no longer claimed — see above; a nested `.git`
that was there when the command started is still bound read-only and still denied. A Landlock-helper run of 31 kernel tests on the same host is the record
of a backend this tree no longer has. These are local-source and disposable-host
validation, not evidence of a published release.
