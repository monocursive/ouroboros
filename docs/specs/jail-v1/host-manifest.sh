#!/usr/bin/env bash
# Reference-host manifest for Jail v1 (§3.2), collected by hand until
# `ouro-jail doctor --json` exists and supersedes it. Read-only: it probes
# nothing beyond one unprivileged `unshare -U true`. It prints no addresses,
# peers or credentials, so its output can be checked in as evidence.
# Usage: ssh <account>@<host> 'bash -s' < docs/specs/jail-v1/host-manifest.sh
set -u
say() { printf '%s: %s\n' "$1" "$2"; }
val() { cat "$1" 2>/dev/null || echo "n/a"; }

say manifest_schema "ouro.jail.host-manifest/0 (manual, superseded by doctor --json)"
say collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say hostname "$(hostname)"
say virtualization "$(systemd-detect-virt 2>/dev/null || echo n/a)"
say kernel "$(uname -r)"
say kernel_build "$(uname -v)"
say arch "$(uname -m)"
say distribution "$( (lsb_release -ds 2>/dev/null) || (. /etc/os-release && echo "$PRETTY_NAME") )"
say systemd "$(systemctl --version 2>/dev/null | head -1)"
say cpus "$(nproc)"
say mem_total_kib "$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
say swap_total_kib "$(awk '/SwapTotal/ {print $2}' /proc/meminfo)"
say root_fs "$(df -h / | awk 'NR==2 {print $2" total, "$4" free"}')"
say operator "uid=$(id -u) $(id -un)"
say operator_linger "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo n/a)"
say operator_sudo "$(sudo -n true 2>/dev/null && echo passwordless || echo 'none or password')"
say shell_cap_eff "$(awk '/^CapEff/ {print $2}' /proc/self/status)"
for k in kernel/apparmor_restrict_unprivileged_userns kernel/unprivileged_bpf_disabled \
         kernel/perf_event_paranoid kernel/yama/ptrace_scope user/max_user_namespaces \
         kernel/io_uring_disabled; do
  say "sysctl.${k//\//.}" "$(val "/proc/sys/$k")"
done
say cgroup_fs "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || echo n/a)"
say cgroup_root_controllers "$(val /sys/fs/cgroup/cgroup.controllers)"
ucg="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service"
say cgroup_user_service "$([ -d "$ucg" ] && echo present || echo absent)"
say cgroup_user_controllers "$(val "$ucg/cgroup.controllers")"
say cgroup_user_subtree_control "$(val "$ucg/cgroup.subtree_control")"
say bwrap "$(command -v bwrap >/dev/null 2>&1 && bwrap --version || echo 'not installed')"
say userns_unshare_test "$(unshare -U true 2>&1 && echo ok)"
say apparmor_enabled "$(aa-enabled 2>/dev/null || echo unknown)"
say apparmor_profile_files "$(ls /etc/apparmor.d 2>/dev/null | grep -iE 'userns|bwrap|ouro' | tr '\n' ' ')"
say apparmor_loaded_bwrap_ouro "$(sudo -n aa-status 2>/dev/null | grep -iE 'bwrap|ouro' | sed 's/^ *//' | tr '\n' ' ')"
say kconfig_bpf "$(grep -E '^CONFIG_(BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF)=' "/boot/config-$(uname -r)" 2>/dev/null | tr '\n' ' ')"
say btf_vmlinux "$([ -r /sys/kernel/btf/vmlinux ] && echo present || echo absent)"
say beam_present "$(command -v erl >/dev/null 2>&1 && echo yes || echo no)"
say ouro_binaries_on_path "$(for b in ouro ouro-jail ouro-ledger; do command -v "$b"; done 2>/dev/null | tr '\n' ' ')"
