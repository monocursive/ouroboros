# J3: agent execution

Implemented on the named x86-64 Linux lane, 2026-09-22 to 2026-09-23, on a
stock host: Ubuntu 26.04.1, kernel 7.0.0-31, bubblewrap 0.11.1, the
distribution's user-namespace restriction left on, no sysctl, AppArmor
profile, file capability or setuid helper. The unprivileged `ouro-ci` account
runs everything. Live evidence is recorded under [`evidence/`](evidence/):

- [`j3-test-log-2026-09-23-review-fixes-ouro-ci.txt`](evidence/j3-test-log-2026-09-23-review-fixes-ouro-ci.txt):
  the full conformance suite, run `20260923T123309Z-8a5ab780e283` (PASS),
  1027 passed, 0 failed, 9 ignored (subprocess helpers invoked by their live
  tests, one optional Unicode data test and one documentation example). It
  includes every J1, J2 and J3
  suite, plus live refusal of credential and launch files reached through a
  writable grant's bind-mount alias, inherited io_uring stdio, and a stopped
  sock_diag dump.
- [`j3-doctor-2026-09-23-review-fixes-ouro-ci.json`](evidence/j3-doctor-2026-09-23-review-fixes-ouro-ci.json):
  `doctor --json` in the delegated user scope, 25 rows, including the four
  `agent` rows measured by one real run and `nested_user_namespace`
  unavailable, as a stock host should report.
- [`j3-host-manifest-2026-09-23-review-fixes-ouro-ci.txt`](evidence/j3-host-manifest-2026-09-23-review-fixes-ouro-ci.txt):
  the host as measured for that run.
- [`unixpeer-spike-2026-09-22-ouro-ci.txt`](evidence/unixpeer-spike-2026-09-22-ouro-ci.txt)
  and [`landlock-nesting-probe-2026-09-22-ouro-ci.txt`](evidence/landlock-nesting-probe-2026-09-22-ouro-ci.txt):
  the measurements behind the host-peer mechanism and the unprivileged
  nesting decision.

The run name identifies the base revision. The conformance driver copied the
working-tree review fixes into that run, including mount-alias validation,
anonymous-inode stdio refusal and stop-aware socket diagnostics. Its remote
run directory was removed after the passing result. The earlier J3 run
`20260923T094510Z-6bb5a34192ac` remains archived in the original
`j3-*-2026-09-23-ouro-ci` evidence files; it predates these fixes.

Every slice was reviewed adversarially before integration, with mutation
testing of its enforcement points; the fixes and the decisions they forced are
in [review-resolutions.md](review-resolutions.md) (revisions 9 to 11).

## Operator setup

`agent`, `tool` and `build` need nothing beyond an installed bubblewrap: no
host configuration is required ([§3.2](../jail-v1.md#32-initial-support-matrix)).
`none` and explicit ceilings need the systemd user delegation that stock
systemd provides; run the supervisor inside a transient user scope, as the J2
document describes. Launch profiles are operator files under
`<config-dir>/launch/`, mode 0600; the bundled ones under
`crates/ouro-jail/profiles/launch/` are experimental examples, copied only by
the operator.

## What `agent` is on a stock host

One bubblewrap layer with its own network namespace (loopback only). The only
network path is the outside HTTP proxy, reached through a trusted in-namespace
bridge on `127.0.0.1:3128`; proxy variables point there. Host pathname Unix
sockets are unreachable through seccomp user-notification mediation of
`connect`, with the authorized proxy socket admitted by its pinned identity.
Contained profiles create sockets only in AF_UNIX (per profile), AF_INET and
AF_INET6. A vendor's own unprivileged sandbox (Landlock, seccomp) starts
inside and restricts its child; one that needs a nested user namespace fails
visibly, and the receipt says `nested_user_namespace: unavailable`. The named
limits of the mechanism are in [§10](../jail-v1.md#10-network-mediation).

## Acceptance map

| Gate | Tests (all live on the reference host unless portable) |
|---|---|
| S03 | `conformance_j3_agent`: `s03_a_landlock_and_seccomp_inner_sandbox_starts_and_restricts_its_child`, `s03_each_outer_boundary_reversal_fails_and_changes_nothing`, `s03_a_namespace_inner_sandbox_fails_visibly_and_the_receipt_says_unavailable`, `s03_the_named_limits_are_what_the_specification_says` |
| N01 | `n01_direct_tcp_udp_ipv6_and_a_proxy_ignoring_client_fail`, plus the socket-family refusal test for every contained profile |
| N02 | `n02_allowed_and_denied_requests_through_the_bridge_yield_one_proxy_result_each` (live); `portable_proxy` N02 cases |
| N03 | `n03_address_and_host_rules_hold_end_to_end` (live); `portable_network_rules` (every frozen case, the full Unicode 17.0.0 IDNA conformance file) and `portable_proxy` N03 cases |
| N04 | `n04_bridge_death_fails_closed_and_is_recorded`, proxy death, header/saturation budgets (live); `portable_proxy` N04 cases |
| N05 | `n05_host_peers_existing_late_aliased_and_in_every_grant_are_unreachable`, `n05_same_attempt_ipc_and_scm_rights_work_and_datagram_sockets_are_refused`, `n05_a_proxy_replaced_before_the_first_connect_is_never_reached`, `n05_a_proxy_replaced_after_the_first_connect_is_never_reached`, `n05_child_path_and_mount_changes_cannot_redirect_the_bridge`; `unix_peer_linux`; the stopped `sock_diag` dump unit test |
| C01 | `conformance_j3_credentials` and `portable_launch` C01 cases, including `c01_bind_alias_of_writable_source_refuses`; `c01_an_agent_launch_profile_stages_both_credential_modes_through_run` |
| C02 | `conformance_j3_credentials` and `portable_launch` C02 cases, including resumable cleanup through `gc` |
| R05 | `conformance_j3_none`: `r05_clean_none_evidence_stays_unprotected`, `r05_same_uid_tampering_is_outside_local_evidence_assurance` |
| R06 | `conformance_j3_none`: the five `r06_*` cases (live target escape, descendant escape, zombie detection both ways, replaced leaf) |
| X06 | `x06_no_notification_sockdiag_proxy_or_bridge_descriptor_reaches_the_target`, `x06_none_reserved_names_and_private_channels_do_not_reach_the_child` |

## Known gaps

- The permissive `agent` filter variant (nested namespace setup) is unit-tested
  only; no reference-conformance host permits nested user namespaces.
- A `bind_ro` digest is recorded only on an immutable filesystem; the
  reference host mounts none, so the digest-present path is unit-tested only.
- Listing network interfaces fails inside contained profiles (netlink is not in
  the socket-family list); resolution and ordinary sockets are unaffected.
- A vendor sandbox that needs a nested user namespace cannot start inside
  `agent` on a stock Ubuntu host; running such a vendor with its own sandbox
  off gives its tool commands the agent's jail authority
  ([north star §4.6](../../../north-star.md#46-nesting)).
- A doctor killed with SIGKILL leaves its probes' temporary directories.
  They are in the system temporary directory, which `gc` never searches, so
  they stay until the operator removes them. `gc` kept attempts with no final
  receipt until J4, whose reconciliation now handles them (jail-v1 §14.2).
- No real agent run (A01) had been recorded at J3. The first runs are recorded
  in [agent compatibility](agent-compatibility.md) (2026-09-23, revision 12);
  the binary reports every launch profile experimental, and the record carries
  the support claim (revision 19).
