#!/usr/bin/env bash
# Reference-host manifest for Jail v1 (§3.2), collected by hand until
# `ouro-jail doctor --json` exists and supersedes it. Read-only: it probes
# nothing beyond one unprivileged `unshare -U true`. It prints no addresses,
# peers or credentials, so its output can be checked in as evidence. It does
# print the short hostname, which is a provider-assigned label rather than a
# routable address.
#
# A missing tool is recorded as `unavailable: <reason>`, never as a blank
# value: the script used to print fifteen empty fields and exit 0 when the
# tools were absent, and the driver gates the evidence on that exit status, so
# an empty manifest was checked in as if it were a measurement. The facts §3.2
# requires -- kernel, kernel_build, arch, os -- are required here too, and the
# script exits 1 if any of them could not be determined.
# Usage: ssh <account>@<host> 'bash -s' < docs/specs/jail-v1/host-manifest.sh
set -u
missing=0
say() { printf '%s: %s\n' "$1" "$2"; }

# A fact §3.2 requires. Blank means the manifest is not a measurement.
req() {
  if [ -z "${2:-}" ]; then
    say "$1" "unavailable: ${3:-could not be determined}"
    missing=$((missing + 1))
  else
    say "$1" "$2"
  fi
}

# A fact that may legitimately be absent on some host; it is named, not blank.
opt() {
  if [ -z "${2:-}" ]; then
    say "$1" "unavailable: ${3:-not present on this host}"
  else
    say "$1" "$2"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# The contents of a file, or a named reason.
val() {
  if [ -r "$1" ]; then
    cat "$1" 2>/dev/null || echo "unavailable: unreadable"
  else
    echo "unavailable: no $1"
  fi
}

# Run a command only when it exists, so a missing tool names itself.
via() {
  local tool="$1"
  shift
  if have "$tool"; then
    "$@" 2>/dev/null
  else
    return 1
  fi
}

say manifest_schema "ouro.jail.host-manifest/0 (manual, superseded by doctor --json)"
req collected_at "$(via date date -u +%Y-%m-%dT%H:%M:%SZ)" "date is not installed"
opt hostname "$(via hostname hostname)" "hostname is not installed"
opt virtualization "$(via systemd-detect-virt systemd-detect-virt)" "systemd-detect-virt is not installed"
req kernel "$(via uname uname -r)" "uname is not installed"
req kernel_build "$(via uname uname -v)" "uname is not installed"
req arch "$(via uname uname -m)" "uname is not installed"
req distribution "$( (via lsb_release lsb_release -ds) || ( [ -r /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME" ) )" "neither lsb_release nor /etc/os-release"
opt systemd "$(via systemctl systemctl --version | head -1)" "systemctl is not installed"
opt cpus "$(via nproc nproc)" "nproc is not installed"
opt mem_total_kib "$( [ -r /proc/meminfo ] && via awk awk '/MemTotal/ {print $2}' /proc/meminfo )" "no /proc/meminfo or no awk"
opt swap_total_kib "$( [ -r /proc/meminfo ] && via awk awk '/SwapTotal/ {print $2}' /proc/meminfo )" "no /proc/meminfo or no awk"
opt root_fs "$(via df df -h / | via awk awk 'NR==2 {print $2" total, "$4" free"}')" "df or awk is not installed"
req operator "$(via id sh -c 'echo "uid=$(id -u) $(id -un)"')" "id is not installed"
opt operator_linger "$(via loginctl loginctl show-user "$(id -un 2>/dev/null)" -p Linger --value)" "loginctl is not installed"
opt operator_sudo "$(have sudo && { sudo -n true 2>/dev/null && echo passwordless || echo 'none or password'; })" "sudo is not installed"
opt shell_cap_eff "$( [ -r /proc/self/status ] && via awk awk '/^CapEff/ {print $2}' /proc/self/status )" "no /proc/self/status or no awk"
for k in kernel/apparmor_restrict_unprivileged_userns kernel/unprivileged_bpf_disabled \
         kernel/perf_event_paranoid kernel/yama/ptrace_scope user/max_user_namespaces \
         kernel/io_uring_disabled; do
  say "sysctl.${k//\//.}" "$(val "/proc/sys/$k")"
done
opt cgroup_fs "$(via stat stat -fc %T /sys/fs/cgroup)" "stat is not installed or /sys/fs/cgroup is absent"
say cgroup_root_controllers "$(val /sys/fs/cgroup/cgroup.controllers)"
ucg="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service"
say cgroup_user_service "$([ -d "$ucg" ] && echo present || echo absent)"
say cgroup_user_controllers "$(val "$ucg/cgroup.controllers")"
say cgroup_user_subtree_control "$(val "$ucg/cgroup.subtree_control")"
opt bwrap "$(via bwrap bwrap --version)" "bubblewrap is not installed"
opt userns_unshare_test "$(have unshare && { unshare -U true 2>&1 && echo ok; })" "unshare is not installed"
opt apparmor_enabled "$(via aa-enabled aa-enabled)" "aa-enabled is not installed"
opt apparmor_profile_files "$(ls /etc/apparmor.d 2>/dev/null | grep -iE 'userns|bwrap|ouro' | tr '\n' ' ')" "no /etc/apparmor.d entry matches"
opt apparmor_loaded_bwrap_ouro "$(have sudo && sudo -n aa-status 2>/dev/null | grep -iE 'bwrap|ouro' | sed 's/^ *//' | tr '\n' ' ')" "aa-status needs privilege this account may not have"
opt kconfig_bpf "$(grep -E '^CONFIG_(BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF)=' "/boot/config-$(uname -r 2>/dev/null)" 2>/dev/null | tr '\n' ' ')" "no readable /boot/config-<release>"
say btf_vmlinux "$([ -r /sys/kernel/btf/vmlinux ] && echo present || echo absent)"
say beam_present "$(have erl && echo yes || echo no)"
opt rust_toolchain "$(PATH="$HOME/.cargo/bin:$PATH" cargo --version 2>/dev/null)" "cargo is not installed"
opt ouro_binaries_on_path "$(for b in ouro ouro-jail ouro-ledger; do command -v "$b"; done 2>/dev/null | tr '\n' ' ')" "none on PATH"

# The manifest is evidence only if the facts §3.2 requires are in it.
if [ "$missing" -gt 0 ]; then
  say manifest_status "incomplete: $missing required fact(s) could not be determined"
  exit 1
fi
say manifest_status complete
