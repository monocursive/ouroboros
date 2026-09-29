# Endpoint Security entitlement request

**Submitted by the operator on 2026-09-29; awaiting Apple review.**
Request ID: `S9YJTLLH28`. The confirmation page was verified in Brave under the
Monocursive developer account. Apple says it will review the request and
contact the applicant with a status update; it gives no review deadline.
Submission is not entitlement approval. This is separate from the deferred
minisign/release-repository decision.

Submitted through [Apple's System Extension entitlement request](https://developer.apple.com/contact/request/system-extension/).
The prepared request text is retained below.

## Application details

- Organization/team: Monocursive, `64SGQ348QJ`.
- Product: Ouroboros / `ouro-jail`, a pre-release local execution sandbox.
- Proposed App ID: `com.monocursive.ouroboros.jail`.
  This identifier has **not** been registered by this task.
- Entitlement: `com.apple.developer.endpoint-security.client`.
- Requested use: development testing and eventual Developer ID distribution.
  Ask Apple which provisioning and App ID configuration they require for
  macOS 27's descendant-scoped client in an app-wrapped command-line helper.
- Contact: the Monocursive developer account's prefilled contact details.
- Company / Product URL: `https://monocursive.com` (company website; no separate
  public Ouroboros product URL has been established for this request).

## Suggested explanation

We are developing Ouroboros, a local execution environment for coding agents
and other commands explicitly launched by the user. Its `ouro-jail` component
enforces filesystem and network policy and records the outcome of each run.
The product is pre-release, with a working Linux backend and a macOS research
prototype.

We request the `com.apple.developer.endpoint-security.client` entitlement to evaluate and implement
the macOS 27 `es_new_descendants_client` API. We intend to create the client
before launching a workload and restrict observation to that helper's
descendant processes. Our initial prototype subscribes to fork, exec and exit
notifications, records audit-token process identities and sequence gaps, and
tests cancellation and descendant cleanup. Seatbelt supplies independent
execution restrictions. We are investigating the behavior when a workload
supervisor or the process holding the ES client dies; we do not yet claim that
the API guarantees complete descendant termination.

The intended product monitors commands launched through Ouroboros. It is not
intended to monitor unrelated applications or users. The initial prototype
records process lifecycle metadata locally and does not collect file contents,
keystrokes or command-line/environment secrets, or upload telemetry. We chose
the descendant-scoped API because it limits visibility to the execution tree
and, according to its macOS 27 documentation, needs neither root nor TCC/Full
Disk Access approval.

The research helper uses an app bundle to carry the provisioning profile and
is launched directly as a command-line executable. The proposed bundle
identifier is `com.monocursive.ouroboros.jail` under team `64SGQ348QJ`.
We request confirmation of
the supported entitlement/provisioning path for this arrangement and approval
for development and eventual Developer ID distribution. We do not plan to install a
system-wide monitoring service for this use case.

## After Apple approves

1. Register or select the App ID under the correct team and enable
   the approved Endpoint Security managed capability.
2. Generate an appropriate macOS provisioning profile for that App ID and the
   signing certificate used for testing. Ensure its entitlement dictionary
   contains `com.apple.developer.endpoint-security.client = true`.
3. Download the profile. Build and run the prepared prototype with it:

   ```sh
   python3 docs/benchmarks/jail/macos_es.py \
     --out /tmp/ouro-es-entitled \
     --identity 'Developer ID Application: Monocursive (64SGQ348QJ)' \
     --profile /absolute/path/to/OuroJailResearch.provisionprofile
   ```

   Use an Apple Development identity instead if Apple supplies a development
   profile; the profile and identity must match. The output directory must
   not exist. The builder embeds the profile, claims the approved entitlement,
   signs the app, verifies its signature, and calls the real ES API.
4. Only a successful real capability call starts lifecycle trials. Inspect
   `result.json`, especially the `custodian_death` case. The runner's eventual
   emergency fixture cleanup must not be counted as successful ES cleanup.

The script does not register identifiers, request profiles, submit applications,
notarize, install a daemon, change SIP/TCC, or enable the production backend.

Sources: [Apple entitlement requirement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client),
[app-wrapped helper signing](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement),
and [managed capability provisioning](https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities).
