# Image attachments in chat: web UI and TUI

Status: source implementation on `codex/chat-image-attachments`. This document keeps
the original design and acceptance target; the as-built notes below distinguish the
implemented behavior and outstanding qualification. Nothing here claims an installed
or published release. See [web behavior](../WEB.md#image-attachments) and
[TUI behavior](../TUI.md#structured-input-attachments-images-effort-b4) for operating instructions.
Design date: 2026-09-14. Implementation validation: 2026-09-15.
Original design baseline: `dev` at `7bea32f5`; implementation baseline: `6058626b`.

### As built

The web composer supports paste, drop, file selection, ordered previews, removal,
retry, image-only messages, and initial messages. The TUI supports Ctrl+V,
`/paste-image`, `/attach`, `/remove-image`, and `/view-image`. Both submit opaque
managed image references through the same owner-routed attachment service. The
native turn path resolves verified content into image parts, pins queued turns to
their selected model, and preserves descriptors in durable history and retries.

The runtime uses a bounded Rust decoder (`ouro-media`) inside existing OS containment,
private content storage, the existing optional content encryption, resumable chunks,
quotas, leases, and conversation pins. Release packaging includes the helper;
source development builds it with `make media` (also included by `make dev`).

Implementation choices that differ from the sketches below:

- Browser uploads use bounded, authenticated LiveView request/reply chunks rather
  than LiveView's multipart staging, keeping source bytes out of plaintext HTTP
  upload directories. Original browser files remain in memory across LiveView
  conversation switches, bounded to 64 sources and 64 MiB per page; session storage
  retains references and recovery metadata. Interrupted transfers resume their
  existing attempt; terminal preparation failures retry with a fresh attempt.
- TUI source snapshots also remain in memory. Private draft metadata and unresolved
  session-start/turn identities survive restart when the owner permits private
  persistence and provides a stable store/principal recovery namespace. Gateway token
  rotation does not change that namespace. Encrypted owners and runtimes without a
  stable namespace require memory-only client drafts. Lost incomplete sources must
  be attached again; accepted images remain owner-durable.
- Both clients use a fresh initial image draft for each new session, preserving the
  original draft identity while an unresolved first message is retried.
- TUI controls use commands and the existing attachment chips rather than a new
  attachment-focus panel. Explicit preview opens a verified private PNG through the
  desktop opener. History always has text labels; inline terminal graphics remain
  optional and are not emitted by this implementation. Preview files are removed
  on normal shutdown; cleanup after a killed client remains a follow-up.
- The catalog exposes supported/unsupported/unknown image input, and admission
  refuses known unsupported models. Per-model evidence badges and image-token cost
  estimates remain follow-ups. No model is called merely to attach or preview.
- Text exports include attachment placeholders. A downloadable bundle containing
  the image files and dedicated attachment telemetry remain follow-ups.

Validation completed locally: runtime/normalizer/integrity/authorization/recovery
tests, actual two-node attachment relay including an offline owner, native model
fixtures verifying image parts and queued model pinning, the Rust library and
integration suites, Clippy, 24 browser tests including desktop/mobile image flows,
and packaging/smoke recipe tests. The full Elixir run passed 4,447 tests with three
peer-bootstrap timeouts in `ForgeTwoNodeTest`; its isolated rerun passed all five
tests. The image-specific checks passed. These results do not make the original
full-suite run green.

After review fixes, local validation passed 1,732 Rust tests, Clippy, Dialyzer, 57 focused
Elixir/protocol tests, seven browser-hook regressions, and all 24 desktop/mobile
browser tests. Regression coverage includes consecutive image-first sessions,
recovery across credential rotation, unfinished and ready images restored together
after conversation switches, bounded source retention, and terminal-failure retries.

Release qualification still requires hosted Linux containment/package runs, actual
desktop clipboard readers and terminal combinations, live-provider image-only and
multi-image requests, and measurements against §12's latency targets. Existing
account credentials were not used to make paid model requests for this validation.

## 1. Outcome

A person copies a screenshot or image, pastes it into the chat composer, sees what
has been attached, writes an optional message, and sends both together. The model
receives the image pixels as image input. The sent message retains its images in
history, including after reconnecting, restarting, or opening the session in the
other client.

This must work in the web UI and TUI, including a local client speaking to a session
on another fleet machine. Attaching an image must not require manually saving it
inside the project, knowing the runtime's filesystem paths, or granting the agent
broader workspace access.

The ordinary text workflow stays familiar. Pasting never sends a message. Attaching
an image does not call a model; sending or queuing the message is the submission
action. The composer must distinguish preparing an image, accepting a message into
the runtime, and delivering input to a model.

### Required product guarantees

| ID | Requirement |
| --- | --- |
| R1 | Build messages with one or multiple pasted images in existing sessions and the initial-message composer; a native reader may require repeated paste gestures. |
| R2 | Send text with images, or images with no text. A completely empty message remains invalid. |
| R3 | Show every pending image before submission, with removal, preparation progress, and errors. |
| R4 | Deliver actual validated image content through the selected model transport, in stable order. |
| R5 | Never silently omit an attached image, substitute its filename for its pixels, or send only the text after an attachment fails. |
| R6 | Preserve the complete draft on rejection; reconcile uncertain submission with its original identity. |
| R7 | Show accepted attachments from durable runtime records in every authorized client. |
| R8 | Work across machines without assuming a shared filesystem or remote clipboard access. |
| R9 | Keep ordinary text paste, multiline editing, IME input, queueing, and existing file mentions working. |
| R10 | Retain the existing authorization, content-encryption, audit, recovery, and terminal-accessibility boundaries. |

## 2. Original implementation baseline and gaps

These observations describe the original inspected baseline, before this change;
they are retained as design context rather than claims about the implemented branch.

| Area | Current source behavior | Work required |
| --- | --- | --- |
| Web composer | `lib/ouroboros/web/live/composer.ex` renders a required textarea and sends a plain string. `priv/static/web/app.js` handles Enter, IME, autosizing, and text draft storage. | Add an attachment tray, paste/drop/file ingestion, structured drafts, and image-only submission. |
| Web submission | `lib/ouroboros/web/live/deck_live.ex` remembers `{text, turn_id}`, retries a runtime-directed verb, and clears the matching text draft on acknowledgment. | Snapshot and reconcile the entire draft, including attachment identities and its revision. |
| Initial message | `lib/ouroboros/web/live/new_session_live.ex` coordinates session creation and the first message. The TUI also has a first-message path. | Carry attachments through creation and first-send recovery without creating duplicate sessions. |
| Web transport | `lib/ouroboros/web/endpoint.ex` has authenticated LiveView sockets, a 65,536-byte urlencoded HTTP parser limit, and no image-upload controller. LiveView is pinned to 1.2.11. | Use bounded LiveView uploads and authenticated attachment reads; do not put image bytes in ordinary form events. |
| TUI clipboard | `tui/src/clipboard.rs` reads PNG through `pngpaste`/`osascript` on macOS or `wl-paste`/`xclip` on Linux, with text fallback, a 16 MiB limit, and bounded helpers. | Preserve the useful platform support while adding precise outcomes and a runtime upload path. |
| TUI staging | `tui/src/ui/mod.rs` runs clipboard work off the UI thread and writes beneath the reported workspace in `.ouroboros/images`. | Stage privately on the client, transfer bytes to the owner, and bind completion to the originating draft. A reported remote workspace path is not a local destination. |
| TUI draft | `tui/src/model.rs` has attachment chips and a structured `TurnInput`; `tui/src/ui/app/session.rs` handles paste, removal, submit, and retries. | Extend this model rather than build a second composer. Remove text-only assumptions. |
| TUI history | `note_sent_images` adds client-local image entries because accepted-input events do not carry the attachment list. `tui/src/images.rs` supports Kitty/iTerm2 rendering and text placeholders. | Replace local-only history insertion with a shared durable projection and authenticated image retrieval. |
| Public turn schema | `gateway/methods.ex`, `gateway/methods/contract.ex`, and `session/turn_request.ex` accept text plus up to 32 path attachments; the prompt must be nonempty on the structured public path. | Add managed image references and permit image-only turns consistently. |
| Attachment authorization | `interactive/task/turns.ex` checks that path attachments are regular files inside the leased workspace. Steering uses that boundary too. | Preserve path checks; introduce a separate authorization path for runtime-owned uploaded images. |
| Native model input | `provider/native/attachments.ex` recognizes PNG/JPEG/GIF/WebP signatures, stages images with hashes, caps each at 20 MiB and the total at 64 MiB. `provider/native/model/req_llm.ex` reads and hash-checks staged images into image content parts. | Add full bounded validation, managed references, model-specific admission, and durable descriptors. Signature recognition alone is not full image validation. |
| Operational content | `audit/content.ex` supports optional encryption and inventories managed native attachments. | Include the new store, manifests, staging, derivatives, and caches in the same policy. |

The TUI's early capability refusal currently returns before its clipboard reader
can perform text fallback. The replacement must classify text independently of
image support. Clipboard responses also need an explicit session/draft identity;
applying a delayed result to whichever composer is currently open is insufficient.

## 3. Scope and explicit boundaries

The first complete release includes clipboard images, selecting image files,
dropping image files in the web composer, multiple attachments, previews, removal,
image-only messages, first messages, follow-ups, durable history, runtime recovery,
and remote session ownership. Both clients use one backend attachment contract.

The guaranteed source formats are PNG, JPEG, static WebP, and single-frame GIF.
Clipboard providers may already convert a screenshot to PNG. Animated GIF, animated
WebP, APNG, SVG, PDF, HEIC/HEIF, TIFF, video, audio, and arbitrary file uploads are
outside this release. Report an unsupported format and retain the draft. Never
quietly take the first animation frame. Existing workspace file mentions keep their
existing behavior.

Image editing, annotation, cropping, OCR-only substitution, remote-image URL
fetching, clipboard synchronization over SSH, shared drafts across different
clients, and automatic image forwarding to subagents are separate work. Existing
authorized history/context propagation must nevertheless preserve any image
references it already carries.

New managed images are supported for `send_message`, `follow_up`, and an explicit
retry of a failed turn. The first release does not inject them through `steer`:
that path currently has different acceptance and retry semantics. If a TUI draft
with managed images is in Steer mode, keep it intact and offer **Queue message**.
Never silently change the verb or drop the images. Legacy path-based steering is
not broadened by this work.

## 4. Shared composer behavior

### 4.1 Draft identity and state

A draft belongs to an authenticated client instance, session owner, and session
ID, or to a pending session-creation ID. Each edit produces a monotonically
increasing `draft_revision`. Each image gets a stable `client_attachment_id` before
asynchronous processing starts.

The draft contains text, ordered image entries, existing workspace-file mentions,
per-turn options, and any unresolved submission snapshot. An image entry has a
source kind (`clipboard`, `file_picker`, or `drop`), display name, preparation state,
validated descriptor when ready, and a structured error when failed. Client IDs
identify UI work; runtime attachment IDs identify stored content. They are different.

| Image state | Visible treatment | Allowed actions |
| --- | --- | --- |
| Reading | Placeholder and “Reading clipboard…” or “Reading image…” | Cancel/remove. |
| Uploading | Local thumbnail when available, bytes/progress, destination if remote | Remove; continue typing. |
| Preparing | “Preparing image…” while validation/normalization runs | Remove; continue typing. |
| Ready | Preview, name, dimensions, size | Preview/remove; send when the whole draft is valid. |
| Failed | Persistent error on the entry, with a reason | Retry where meaningful, replace, or remove. |
| Needs reattachment | Label retained after source bytes become unavailable | Attach again or remove. |
| Removed | No longer in the draft | No delayed callback may restore it. |

Submission has its own states: editable, submitting, acceptance unknown, accepted,
or rejected. Image preparation success is not message acceptance. An accepted queued
message is labeled **Queued**, not delivered or seen by the model.

### 4.2 Paste semantics

1. Act only on an explicit paste gesture in the composer or its attachment control.
   Do not monitor, periodically read, or read the clipboard on focus.
2. A text-only clipboard follows normal text paste, preserving selection replacement,
   newlines, Unicode, undo, and IME behavior. Image capability cannot block this.
3. When usable image data is exposed, stage images in the order exposed by the
   clipboard. Prefer actual image/file items; do not scrape HTML `<img>` elements
   or fetch `src` URLs.
4. If the same paste exposes images and nonempty plain text, append the images and
   insert that text once at the selection. Ignore HTML markup. Clipboard text can
   be an image's alternate representation; the UI cannot reliably infer intent,
   so any exposed plain text is visible and editable before Send.
5. For native readers that can expose only an image representation, attach that
   image; do not invent associated text. Text is read as fallback when no image is
   present. Document this platform difference.
6. Recognize each item once. In the browser, use `items` with `files` as fallback,
   not as a second independent batch. Within a draft, identical normalized content
   is deduplicated in first-occurrence order with “Image already attached.” Separate
   messages may intentionally contain the same image.
7. Never turn pasted path-like text, a URL, Markdown, or terminal escape text into
   an attachment automatically. Explicit Attach/file selection gives that authority.
8. A partially valid batch shows both ready entries and per-item failures. Send
   remains blocked until failed entries are retried successfully or removed. Never
   silently send the successful subset.

Pasting, selecting, or dropping an image authorizes preparation and transfer to the
selected Ouroboros runtime. The attachment help explains that uploads happen before
Send and expire if abandoned. No model call occurs until submission.

### 4.3 Submission and recovery

Send is available when text contains a non-whitespace character or at least one
ready image exists, every included entry is ready, scope allows sending, the session
is writable, and there is no known model/transport incompatibility with the complete
request. Unknown model capability follows section 9. Browser
`required` on the textarea cannot remain the source of truth.

On Send, freeze text, ordered refs, workspace attachments, options, owner/session,
revision, and `turn_id`. Disable submission of that snapshot. A second click or key
repeat must not create a second turn. Keep the normal runtime-directed busy/queue
retry behavior, reusing the complete snapshot and the same turn ID.

The user may continue composing the next draft during the request. An acknowledgment
removes only entries and text belonging to the submitted revision; it never clears
subsequent typing, a later paste, or another session's draft. A rejection restores
or retains the submitted snapshot without overwriting a newer draft; if necessary,
show the rejected message separately with **Restore** and **Retry**.

For an uncertain outcome, show “Checking whether this message was accepted…” and
reconcile against the original turn ID. Reconnect and retry use the frozen envelope;
they must not restage images under new identities or generate another turn ID.
Provide an explicit way to copy/restore the draft if reconciliation remains blocked.

An explicit retry of a known failed turn follows the existing retry operation and
creates/reuses its defined retry identity with the same retained image content.
This differs from retrying an unacknowledged network request.

### 4.4 Image-only messages and ordering

An image-only message has `prompt: ""` and at least one validated managed image.
Preserve an intentionally whitespace-only draft as typed, but use trimmed text only
for emptiness checks. Do not insert a hidden “Describe this image” prompt. The user
message in history contains its images and no invented text. If a transport cannot
represent this input, fail explicitly before dispatch.

The provider message order is text when present, then managed images in composer
order, then existing path-attachment contributions in their established order.
There is no interleaved rich-text/image editor in this release. Number previews
“Image 1”, “Image 2”, and so on so references such as “compare the second image” are
unambiguous. Upload completion order must not reorder images.

### 4.5 First message and session switching

Initial-message composers have the same paste and preview behavior. Before a
runtime session exists, images belong to an authenticated, expiring draft on the
selected owner. Require a selected destination before uploading; local preview can
exist while destination selection or sign-in is incomplete.

Starting follows a recoverable sequence: create/reconcile the session using the
existing stable start identity, bind the prepared draft to that session, then send
the frozen first message with a stable turn ID. Binding is idempotent and permitted
only for the draft creator and intended session. If first-send fails, resume in the
created session with the images intact rather than creating another session.

Session navigation retains per-session drafts. Every asynchronous completion carries
owner, session/pending-start ID, draft ID, revision, and attachment ID; apply it only
to that originating draft. Removal installs a cancellation tombstone before canceling
I/O so late success cannot resurrect an entry. A changed destination never silently
retargets an upload: mark it “Move images to selected computer” and require that
explicit action before copying to the new owner.

## 5. Web UI specification

### 5.1 Layout and actions

Add an **Attach image** button with a paperclip/image icon beside the composer.
Its accessible name is the action, not the icon name. It opens a multi-select file
picker restricted to the supported formats. The same control appears in the initial
message form.

Place a wrapping attachment tray above the textarea, inside the composer surface:

```text
┌────────────────────────────────────────────────────────────────────┐
│ [thumbnail] Image 1             [thumbnail] Image 2                 │
│ screenshot.png · 1440 × 900     diagram.png · Preparing…            │
│ 820 KiB            [Remove]                           [Remove]     │
├────────────────────────────────────────────────────────────────────┤
│ What causes the layout difference between these screens?           │
│                                                                    │
│ [Attach image]                           Preparing 1 image… [Send]  │
└────────────────────────────────────────────────────────────────────┘
```

Use roughly 80 × 64 CSS-pixel thumbnail bounds on desktop, `object-fit: contain`,
and a neutral/checkerboard background for transparency. Preserve aspect ratio and
reserve dimensions before decoding to avoid layout jumps. Each card has a preview
button, a separate remove button, a visually shortened name, and full accessible
metadata. Use `textContent`/normal escaped template output for filenames.

At narrow widths, wrap or scroll the tray within the composer, with at most two
visible rows before internal scrolling. Keep the text field and Send control usable
at 320 CSS pixels and 200% zoom. Do not let a large screenshot determine page width
or consume the entire viewport. Touch controls have at least 44 × 44 CSS-pixel hit
areas; keyboard focus is visible.

Clicking a preview opens an accessible dialog with a contained image, dimensions,
image index, previous/next controls, and close. Escape closes it and returns focus
to the invoking image. The dialog does not remove an attachment or submit a message.
No OCR-generated alt text is required: use “Attached image 1: screenshot.png,
1440 by 900 pixels” and preserve any user-provided caption in the message text.

### 5.2 Browser paste and drop

Register the paste listener on the composer, with a single ingestion function shared
by clipboard, file input, and drop. Process `ClipboardEvent.clipboardData` image/file
items from that gesture. The standard exposes non-text items through `items` and
`files`; browser behavior still needs real-platform qualification.
[Clipboard API and events](https://www.w3.org/TR/clipboard-apis/).

Do not require `navigator.clipboard.read()` for ordinary paste. A separate optional
**Paste image** button may use it only after feature detection and a user click;
if denied or unsupported, keep focus and explain the native paste/file-picker path.
Do not repeatedly ask for permission or report support solely from API presence.

Call `preventDefault()` only when handling image/file items, inserting any plain
text explicitly once. If no image/file is handled, leave the browser's text paste
alone. Do not cancel Enter during IME composition. Enter/Shift+Enter keep their
existing send/newline semantics after the image-ready check is added.

Show a drop affordance over the composer while an image file is dragged there.
Prevent browser navigation for file drops on the active chat surface, explain where
to drop, and ingest only on the composer target. Text selection dragging remains
normal editing. Reject directories and non-image files with specific errors.

### 5.3 Upload integration

Use Phoenix LiveView's upload lifecycle (`allow_upload`, `live_file_input`, progress,
cancellation, and a bounded writer). It already supplies chunked uploads and entry
validation. Runtime image validation remains authoritative; file metadata is not
trusted. [LiveView uploads](https://hexdocs.pm/phoenix_live_view/uploads.html).

Feed clipboard `File` objects into the named uploader with the supported hook
`upload`/`uploadTo` API, verified against the pinned 1.2.11 dependency. Keep stable
entry-to-draft mappings across DOM patches.
[LiveView JavaScript interoperability](https://hexdocs.pm/phoenix_live_view/js-interop.html).

Use `auto_upload: true`; an entry becomes Ready only after the session owner has
validated, normalized, and stored it. A receiving web node can relay bounded chunks
to another owner through the shared attachment service. Avoid retaining an entire
remote upload in LiveView assigns or a BEAM mailbox. Backpressure and cancellation
must reach the writer and the owner.

Do not increase the ordinary form parser cap to accommodate images. LiveView's
authenticated upload channel is a separate body path. Verify the custom
`Web.LiveSocket` authentication and upload-channel behavior, including reconnection
and scope revocation, before enabling uploads. The public static directory must
never contain user attachments.

Expose completed thumbnails/content through authenticated controller routes, for
example `GET /attachments/:id/thumbnail` and `GET /attachments/:id/content`, with
owner/session resolution checked on the server. The actual route shape can include
a session locator; it must never accept a filesystem path or arbitrary upstream URL.

Responses use verified MIME types, `X-Content-Type-Options: nosniff`,
`Cache-Control: private, no-store`, and the existing no-referrer policy. Do not put
credentials in URLs. Local draft previews use object URLs that are revoked on
removal, replacement, navigation disposal, or successful reconciliation. If CSP is
configured, allow only the required same-origin/blob image sources.

### 5.4 Persistence and accessibility

Continue storing text drafts in sessionStorage, but store only attachment IDs,
display metadata, revisions, and submission snapshots there. Never base64 images
into browser storage. Prepared drafts are recovered from the owner's private store
after reload and reconciled before Send is enabled. Unfinished uploads can restart
while the original `File` is still in memory; after reload, show “Attach this image
again” rather than claiming their bytes survived.

Do not share unsent drafts across tabs by default. A per-tab instance ID prevents
two tabs editing the same attachment collection. A restored browser tab revalidates
authorization and expiry; browser storage is never an authority token.

Announce additions, readiness, removal, and actionable errors through a polite live
region. Do not announce every percentage update. Send's blocked reason is adjacent
and accessible. Progress is both textual and visual; color alone never identifies
an error. Attach, preview, remove, retry, and the image dialog work by keyboard.

## 6. TUI specification

### 6.1 Clipboard and terminal constraints

Keep `paste_image` as the configurable action, with Ctrl+V as the existing default.
Expose it in help and the command palette; add an explicit `/paste-image` command
so terminals that intercept the key still have a usable path. Standard terminal
paste, including Cmd+V or Ctrl+Shift+V as configured by the terminal, may produce
text or a pasted path. Do not promise those shortcuts transport image bytes.

Bracketed paste identifies pasted character input; it is not a general binary-image
transport. Preserve its protection against pasted newlines executing actions. OSC 52
must not be treated as portable image clipboard access. Image display protocols are
a separate concern. [XTerm control sequences](https://invisible-island.net/xterm/ctlseqs/ctlseqs.html).

| Environment | Clipboard behavior | Required fallback |
| --- | --- | --- |
| macOS, TUI on local desktop | Probe `pngpaste`, then the existing AppleScript PNG path; text via `pbpaste`. | Explicit Attach with a local image path; explain a reader failure. |
| Linux Wayland | Probe usable `wl-paste` and an image MIME representation. | Attach a local image; identify missing `wl-clipboard`. |
| Linux X11 | Probe usable `xclip` against the clipboard selection. | Attach a local image; identify missing `xclip` or display access. |
| Local TUI, remote runtime | Read the local clipboard and upload bytes to the selected session owner. | Same local Attach path. Never write to the remote workspace path locally. |
| TUI running on an SSH host | Only the host's available clipboard is accessible. | Save/copy the image to that host and explicitly attach it, or use a local TUI/web client connected to the runtime. |
| tmux/screen, VS Code terminal, unknown terminal | Clipboard read and graphics support are separately detected. | Explicit paste command and text attachment cards, regardless of graphics support. |
| Screen reader mode or `OURO_NO_IMAGES` | Attach and send normally; never emit inline graphics. | Fully labeled text cards and attachment details. |

Use available tools without mandatory new global installations where current
fallbacks suffice. Keep `OURO_CLIPBOARD_IMAGE_COMMAND` as an operator-configured
escape hatch, never a value supplied by a message, image, or remote runtime.

Return distinct outcomes: image, text, empty, no compatible reader, reader denied,
timeout, too large, invalid image, and read failed. Do not collapse a timeout or
oversized image into “clipboard empty.” Fallback from “no image representation” to
text is normal; operational failures remain visible. Helpers run off the render/input
thread, with one total five-second operation deadline, bounded output, and process
termination/reaping on cancellation.

### 6.2 Explicit file attachment

Add `/attach <path>` and a command-palette **Attach image file** action. The path is
resolved on the TUI host, opened there, and uploaded as bytes. State that locality in
the prompt, especially when the session owner is remote. This differs from `@` file
mentions, whose paths belong to the session workspace.

Support quoted paths, spaces, Unicode, and `~` expansion without shell evaluation.
Do not expand commands, execute pasted text, or enumerate arbitrary glob patterns.
Validate the opened regular file and read a bounded snapshot; subsequent edits to
the source file must not change a prepared attachment. A user-selected path may be
outside the agent workspace because the user is explicitly supplying those bytes.
This grants no additional filesystem access to the agent.

### 6.3 Draft presentation and keyboard behavior

Use the existing composer attachment model and chip row, extended with explicit
state and dimensions. A compact representation is sufficient on every terminal:

```text
Images 2 · 1.8 MiB
[1 screenshot.png 1440×900 · Ready] [2 diagram.png · Uploading 62%]
> compare the spacing in these screenshots
Attach image: Ctrl+V     Attach file: /attach     Send: Enter
```

At narrow widths, render a bounded vertical list or “2 images · 1 preparing”; the
attachment panel exposes the complete list. Never render raw base64 or private
storage paths. Escape control characters, ANSI, OSC, newlines, and bidi-control
characters in names and diagnostics before drawing or exporting them.

Tab/Shift+Tab moves among the editor and attachment controls. In attachment focus,
arrow keys select an image, Enter opens details/preview, and Delete/Backspace removes
the selected entry. In editor focus, Backspace retains ordinary text editing. If
the editor is empty, the first Backspace selects the newest attachment and a second
removes it; make the selection visible. Escape closes the attachment panel and
returns to editing; it does not discard the draft.

Respect configurable key bindings and existing higher-priority session controls.
Ctrl+C keeps the TUI's current interrupt/exit policy; do not overload it as image
removal. Up-arrow queue retraction or prompt history must not consume an image-only
draft as though the composer were empty. Queue recall restores the full envelope.

### 6.4 Preview and asynchronous lifecycle

Inline pixels are optional; attaching and sending are not. Reuse the existing
Kitty/iTerm2 rendering where qualified, with normalized PNG preview derivatives.
Sixel remains a labeled placeholder until an encoder is implemented and tested.
Do not infer clipboard access from graphics support or vice versa.

A details panel shows index, display name, dimensions, size, state, and destination.
Limit preview geometry to the available panel and a small row budget; do not insert
an 80-row screenshot into the composer. Clear graphics on close, scrolling, resize,
session switch, and shutdown. Under multiplexers or failed graphics negotiation,
fall back without losing attachments or disrupting the prompt.

Every clipboard/read/upload result carries its originating draft identity, not just
an `Image(path)` outcome. Use cancellable worker tasks and bounded channels. Multiple
paste actions reserve ordered slots immediately; they may prepare concurrently
without changing that order. A full tray is rejected before writing another source
file where possible, and any race-lost temporary file is cleaned up.

Store source snapshots in a private client staging directory, never the repository.
Use exclusive creation, random names, no-follow file handling, private permissions,
and cleanup on success, removal, expiry, and next startup after a crash. A successful
owner commit lets the client release the source snapshot. Follow the active content
encryption policy for persistent client data; otherwise use memory or ephemeral
storage rather than silently persisting plaintext under an encryption-required policy.

Persist only the draft metadata and complete unresolved submission snapshot in the
TUI's private state. After restart, revalidate runtime refs and recover their previews.
Do not require the original clipboard contents or file to still exist for a Ready
attachment. Bound preview downloads/cache size, and provide placeholders if the owner
is unreachable. A preview fetch failure never silently removes an image from input.

## 7. Runtime attachment service

### 7.1 Authority and ownership

Introduce an attachment service on the runtime that owns the session. The runtime
owns storage, validation, normalization, immutable descriptors, binding, expiry,
retrieval, and authorization. Clients own temporary source acquisition and their
editable drafts. Provider adapters own conversion from validated images to their
wire format.

Managed attachment authorization is separate from workspace path authorization.
Clients submit opaque IDs, never arbitrary runtime paths. A reference is usable
only in its bound session or its creator's pending draft. Knowing an ID or digest
does not authorize reading or sending it. Before binding, validate the same
authenticated operator/client authority that can start or operate the destination.
Use the runtime's existing credential/scope identity; do not invent a user/account
isolation guarantee that the current shared-token/fleet trust model does not provide.

Keep `authorize_attachment_paths` for legacy `attachments: [path]`. Add a typed
managed-reference resolver, used by normal submission, follow-up, retry, recovery,
and future steering support. Never implement managed images by exempting a special
directory from all workspace checks or widening the agent's writable roots.

### 7.2 Immutable descriptor

An internal descriptor contains:

```json
{
  "id": "att_<opaque-random-id>",
  "version": 1,
  "kind": "image",
  "owner": "<runtime-owner-id>",
  "session_id": "<bound-session-id-or-null>",
  "draft_id": "<creator-draft-id>",
  "display_name": "screenshot.png",
  "source": "clipboard",
  "media_type": "image/png",
  "byte_size": 842137,
  "width": 1440,
  "height": 900,
  "sha256": "<normalized-content-digest>",
  "state": "ready",
  "created_at": "<timestamp>",
  "expires_at": "<timestamp-until-pinned>"
}
```

This example is illustrative, not an existing schema. The private record also
contains authorization, storage and derivative references, source-validation
receipts, and retention pins. Public/session-readable projections expose only the
metadata needed by that scope. Storage paths, credential identities, upload tokens,
source EXIF, and temporary paths are never transcript metadata.

Hash the exact normalized bytes the provider will receive. Store a source digest
privately if needed for upload integrity; it is not interchangeable with the
normalized digest. IDs and storage filenames are unrelated to user-supplied names.
Deduplicate storage only within an authorized ownership domain; never expose a
global “does this hash exist?” endpoint.

### 7.3 Proposed gateway operations

All names below are proposed additions. Register them in the contract table,
capability advertisement, routing, scope checks, documentation, and fixtures.
Use the existing gateway framing rather than embedding a complete image in a turn.

| Operation | Input and purpose | Result / semantics |
| --- | --- | --- |
| `attachment.begin` | Destination session or pending-start draft, client attachment ID, source size/type/name, optional source digest. Requires operate scope. | Opaque upload ID, authoritative limits, chunk size, expiry. Idempotent for the same creator/draft/client ID and metadata. Conflicting reuse fails. |
| `attachment.append` | Upload ID, byte offset, bounded base64 chunk. | Next offset. An exact repeated chunk is acknowledged; a conflicting overlap or gap fails. |
| `attachment.finish` | Upload ID, final source length and digest. | Starts bounded validation and returns `preparing` or the immutable Ready descriptor. Repeating finish never creates another attachment. |
| `attachment.status` | Upload ID or owned attachment ID. | Authoritative offset/state/descriptor/error; reconnect recovery does not depend on a consumed reply. |
| `attachment.touch_draft` | Owned draft ID with its current revision, triggered by actual editing. | Renews the unsent lease; throttle to once per minute. Background status/preview polling does not prolong retention. |
| `attachment.bind_draft` | Pending-start draft ID and newly created session ID. | Idempotent, authorized association of that draft's ready refs with the intended session. No cross-owner rebinding. |
| `attachment.discard` | Upload/attachment ID belonging to this draft. | Idempotently cancel preparation or release the draft reference. It cannot delete content pinned by an accepted turn. |
| `attachment.read` | Authorized ID, variant (`thumbnail`, `content`), offset and bounded requested length. | Bounded chunk, total length, digest, EOF. Read/preview does not consume the attachment. |

`finish` does not block the session coordinator or render loop during decoding.
Status notifications may reduce polling; the status read remains authoritative.
Web upload writers call the same internal service, retaining the same semantics.

Persist the upload ID alongside the client attachment ID as soon as `begin` answers.
After disconnect, query the authoritative offset and resend only from that offset.
After expiry or an unrecoverable validation failure, a user-triggered retry starts a
new upload attempt under the same logical draft entry, with a fresh attempt ID.
Old attempt completions cannot overwrite the new attempt. Retries of a single
attempt's begin/finish remain idempotent. Each `read` response identifies the variant
and its own digest; thumbnail bytes must not be checked against the model-image hash.

The default gateway frame is 1 MiB. Negotiate a decoded chunk no larger than 256 KiB
and small enough for the actual encoded envelope within both endpoints' frame limits.
Account for base64's `4 * ceil(n / 3)` expansion and bounded metadata. Check encoded
length before writing. If a configured frame cannot carry the minimum control
envelope, advertise uploads unavailable with a configuration reason. Never raise
the gateway's global frame limit just to fit an image.

Reserve disk and upload slots before accepting bytes. Enforce limits on actual
received bytes, not the declared length. Use one ordered chunk stream per image and
bounded concurrent images, with backpressure from the owner to the client. Untrusted
append streams must not grow unbounded mailboxes or intermediary-node memory.

### 7.4 Turn contract

Keep the string form and existing path list backward compatible. Add a dedicated
managed-image field rather than overloading paths with magic prefixes:

```json
{
  "jsonrpc": "2.0",
  "id": 41,
  "method": "interactive.send_message",
  "params": {
    "id": "session-123",
    "node": "<session-owner>",
    "turn_id": "client-stable-turn-id",
    "input": {
      "prompt": "Why does this layout overflow?",
      "image_attachments": [{"id": "att_a"}, {"id": "att_b"}],
      "attachments": ["src/layout.css"]
    }
  }
}
```

`image_attachments` is optional. Its entries contain only a validated opaque ID;
reject unknown keys, duplicate refs, nonexistent/expired refs, and cross-session or
cross-owner refs. Count legacy and managed attachments together against the common
32-entry limit. Count all images, including legacy path images, against the total
image byte and provider limits. Empty text is valid only when a managed image is
present and successfully resolved; an empty list does not make an empty turn valid.

Update gateway validation, `TurnRequest`, option-shadowing checks, internal copying,
serialization, exposure checks, retry, and recovery together. Audit both map/keyword
and atom/string-key entry paths. No internal API may bypass image authorization.

Advertise an additive capability such as `image_attachments_v1` and effective limits
on the owning runtime. A new client talking to an older owner disables managed-image
actions with “Update the session's runtime to send pasted images.” Existing text and
authorized path attachments remain usable. An older client can ignore descriptors;
provide a plain “2 images attached” fallback summary in the accepted message metadata.
Do not copy new uploads into the workspace as an automatic compatibility workaround.

### 7.5 Atomicity, identity, and recovery

Before accepting a new turn, resolve every image, verify ownership and readiness,
enforce aggregate/model limits, and pin its immutable content as part of the durable
turn-intent transaction. Only then dispatch or queue the provider request. No provider
call may race ahead of the attachment manifest becoming durable.

The logical fingerprint includes text, ordered managed IDs and normalized digests,
legacy attachment semantics, and request options. It excludes temporary paths,
thumbnails, timestamps, upload offsets, and client preview state. Once accepted,
replaying the same turn ID and envelope resolves to the saved immutable manifest,
even if the original draft lease expired. A changed image under that ID is a conflict.

Use the existing serialized session mutation/checkpoint boundary plus an explicit
attachment reservation/commit record if the stores cannot transact together. Recovery
must distinguish reservation without intent, durable intent without dispatched input,
and a dispatch with unknown acknowledgment. The garbage collector treats reservations
and unresolved durable intents as roots. Orphan reservations are reconciled against
the turn ledger before release; a timeout alone cannot delete accepted content.

If any preflight step fails, accept none of the message and dispatch nothing. A
provider rejection after durable acceptance is a failed turn with its images retained.
Keep the draft-versus-accepted-failure distinction in both clients.

### 7.6 Existing sessions and upgrade behavior

Version the new persisted attachment/turn manifests. Existing text-only and legacy
path-attachment checkpoints remain readable, and their saved fingerprints retain
their original interpretation. Adding an empty field to a struct must not make a
previously accepted turn conflict with its original retry. Introduce the new
fingerprint scheme only for versioned new requests and test mixed histories.

Where old private native history already contains a staged image and digest, a
bounded lazy migration may verify it and create a managed descriptor/pin for that
same session. Do not infer images from prompt text, filenames in logs, or a scan of
the workspace. If an old input cannot be associated with a turn reliably, preserve
the legacy record and state that its historical attachment metadata is unavailable.
Do not invent a retrospective image count.

Existing `.ouroboros/images` workspace files are user/workspace content and are not
automatically deleted by the new attachment collector. New writes use the private
store. Inventory reports can identify legacy artifacts without granting cleanup
authority. Migration must honor existing content encryption and be restartable.

A runtime that cannot read the new manifest version must refuse to resume that
image-bearing session with an upgrade diagnostic; it must not silently resume with
text only. A rollback keeps the new store intact. Capability negotiation for mixed
fleet versions is per session owner, including intermediary gateway support, and
never assumes the client machine's runtime version applies to a remote owner.

## 8. Image validation, normalization, and resource limits

These are proposed default product limits. Publish the effective values from one
runtime policy and intersect with provider/transport constraints. They are not
claims about a vendor's maximums.

| Limit | Proposed value |
| --- | --- |
| Source image size | 20 MiB per image, enforced during receive. |
| Normalized model image size | 20 MiB per image. |
| Images plus legacy attachments | 32 entries per message. |
| Aggregate image size | 64 MiB source and 64 MiB normalized per message, each checked independently. |
| Dimensions | At most 16,384 pixels on either edge and 40 million decoded pixels. |
| Client upload concurrency | 2 active images. |
| Runtime upload concurrency | 8 active images, with 2 concurrent decode workers. |
| Decoding | 5-second total deadline and 512 MiB worker memory ceiling. |
| Draft staging quota | 256 MiB per authenticated client, 1 GiB per runtime, including partials and derivatives. |
| Retained attachment quota | 2 GiB per session and 10 GiB per runtime; configurable by the operator. |
| Thumbnail | Longest edge 320 pixels, at most 256 KiB; generated separately from model content. |
| Partial upload expiry | 10 minutes without progress; 1-hour absolute lifetime. |
| Unsent ready draft expiry | 24 hours without activity; advertised to clients. |

Retained quotas count physical bytes, including encryption expansion and derivatives;
admission budgets source and normalized buffers separately. Explicitly reject quota
exhaustion instead of evicting accepted conversation content. These defaults need
resource qualification on each packaged target before release. Raise the current
TUI's 16 MiB ingestion limit to the negotiated 20 MiB policy; use small derivatives
for display rather than requiring the renderer to load every full-size attachment.

Validate magic bytes and the complete image with a bounded decoder, rejecting
truncation, malformed headers, unsupported formats, animation, excessive dimensions,
and decompression bombs before unbounded allocation. A correct extension, claimed
MIME, browser preview, or native clipboard helper success is not sufficient.

Perform decoding/normalization in an isolated OS process with no network and private
temporary access, not a BEAM scheduler-blocking decoder or a TUI render callback.
Implement the helper in Rust, with pinned dependencies and inclusion in the existing
release packaging; no user-installed image-conversion binary is required. The exact
crate choice and helper entry point are implementation choices, but resource bounds,
format behavior, and packaged target coverage are acceptance gates.

Apply EXIF orientation, remove EXIF/GPS/XMP/comments and unnecessary embedded metadata,
and normalize color interpretation to sRGB. Preserve dimensions and visible content.
Use PNG for clipboard screenshots, transparency, GIF normalization, and lossless
sources; JPEG can remain JPEG with metadata removed without an additional lossy
re-encode when the orientation/color transformation permits. Any required raster
transformation may use PNG. Never silently downscale, crop, or reduce JPEG quality
to fit a limit. If normalization grows beyond the cap, explain the failure and ask
for a smaller source through the ordinary error UI.

Generate a separate sanitized PNG thumbnail, reducing only the derivative's dimensions
if necessary to meet its byte cap. The provider receives full normalized content,
never the thumbnail. Where a provider requires a different format or opaque
background, define and disclose that deterministic transformation in its adapter;
if fidelity cannot be preserved under the configured limits, refuse before dispatch.

Write storage atomically using server-selected paths, exclusive temporary files,
hash verification, private directory/file permissions, and crash-safe promotion.
Avoid symlink traversal and overwriting an existing different blob. Do not extract
archives or invoke a shell with filenames. Remove source bytes after successful
normalization unless an explicit configured retention policy requires them.

## 9. Provider capabilities and model delivery

Distinguish four facts: client acquisition, runtime upload support, transport image
support, and selected-model image support. Existing generic `multimodal` metadata is
not enough to prove all four. The owner returns `supported`, `unsupported`, or
`unknown`, its evidence source/catalog epoch, supported input types, and any known
count, byte, pixel, and context constraints.

Known unsupported: block sending images with an actionable model-selection error.
Unknown: show “Image support hasn't been verified for this model” beside the model
control and allow the ordinary Send action when the transport can encode image input.
Do not add a second confirmation dialog. Preserve the complete request if rejected;
never label an untested model verified. Do not change models or accounts automatically.
Upload and preview may
still occur independently of model support so a user can prepare a draft and then
choose a compatible model.

Recheck at submission and dispatch. Pin the resolved model/transport configuration
for an accepted queued turn, including image policy, so changing the session's model
does not silently reroute an already accepted image message. Future draft messages
use the newly selected configuration. If pinning cannot be honored after recovery,
fail the queued turn explicitly rather than changing its destination.

The native adapter resolves managed refs to verified bytes and constructs real image
content parts alongside text. Adapt per transport through the pinned ReqLLM layer;
do not send browser blob URLs, local paths, attachment IDs, or a textual filename as
substitutes for image input. Only the currently selected configured provider receives
the content. Reuse managed blobs internally instead of keeping a second uncontrolled
copy under native history.

Maintain an implementation qualification table for each exposed connection lane and
tested model: exact model ID, account/transport, date, catalog evidence, observed
image-only/multi-image behavior, payload format, and outcome. A successful mock or
generic capability flag is not a live model qualification. Refresh vendor limits
from official documentation during implementation; do not hardcode remembered limits
into either composer.

Estimate image context usage with the adapter's supported estimator where available.
Otherwise label image contribution unknown; do not claim a text-token estimate covers
the images or show zero image cost. Reject known context overflow before dispatch.
Provider errors must retain attachment count/order and safe diagnostics without
logging base64, signed fetch URLs, image bytes, or credentials.

## 10. History, storage, privacy, and retention

Extend the durable accepted-input/queued-turn projection with sanitized attachment
descriptors and a stable turn/message link. They must be reconstructible from the
saved request/manifest after a crash, not only emitted by the originating client.
Replay, pagination, a second web tab, and a TUI attached later render the same image
list. Pending optimistic entries reconcile by turn ID and attachment ID so acceptance
does not produce duplicates.

Web history shows bounded thumbnails under the user's message; TUI history shows
images where supported and labeled cards everywhere. A missing thumbnail can be
regenerated; a missing original is shown as “Image unavailable.” If required model
input bytes are missing or corrupt, block that turn/retry with an explicit error.
Do not substitute a placeholder into a request while claiming the original image
was included.

Accepted attachments remain pinned for as long as retained turn/history/retry/fork
records require them. Closing a session is not deleting its history. Removing an
unsent image releases only that draft's pin; it cannot remove the same content from
an earlier sent message. Retraction of a queued message preserves its images long
enough to restore the draft. Compaction may exclude older images from future model
context according to the context policy but must preserve their history references.
Make that distinction visible in context inspection.

When compacting an image-bearing history, never claim an image was analyzed if it
was not. A summary can retain the user's accompanying text and known prior assistant
observations, plus a reference to the image; it is not an equivalent replacement for
the pixels. Missing required images during resume must be surfaced. Forking/retrying
history creates authorized destination pins or verified copies before the source
can be collected. No cross-machine absolute paths belong in those checkpoints.

Store images and manifests under a runtime-owned data-directory attachment area,
outside the workspace and `priv/static`. Apply `Audit.Content` encryption when
configured, including derivatives and persistent staging; extend inventory/rotation
coverage. Secure temporary decoding material is deleted on completion and swept
after crashes. Explain that optional application encryption does not encrypt an
operator's original source image or the OS clipboard.

Drafts remain creator-scoped; accepted images follow existing session read scope.
Enforce authorization on every chunk, status, bind, discard, thumbnail, and content
request. Expired/revoked credentials cannot finish an upload or retrieve a cached
private image through the application. Do not treat a bearer-style opaque ID as the
only read check. Fleet membership retains its existing shared trust boundary.

Audit metadata may record sizes, MIME, counts, state changes, safe error codes, and
scoped content digests according to existing policy. Operational image storage and
audit capture are separate: attaching an image must not silently enable raw audit
capture. Image content is untrusted user input; text/OCR inside it does not grant
permission or override tool approvals.

Plain-text/Markdown export contains descriptive attachment placeholders and image
indices. An explicit export including images creates a bundle with verified relative
paths and normalized files, respecting current audit/content export policy. Do not
embed private runtime URLs or absolute local paths. Session deletion and content
purge release all eligible pins, remove derivatives/caches under runtime control,
and leave a metadata tombstone where required by the existing audit policy. Do not
claim deletion from a provider, backup, or a previously exported copy.

## 11. Failure behavior and user-facing copy

| Condition | Required behavior / example copy |
| --- | --- |
| Unsupported format | “This image format isn't supported. Use PNG, JPEG, static WebP, or a single-frame GIF.” Keep other draft content. |
| Animation | “Animated images aren't supported yet. Export a still image to attach it.” |
| Source too large | “This image is larger than 20 MiB.” Show the actual effective limit. |
| Dimensions too large | “This image exceeds the supported dimensions. Attach a smaller version.” Include dimensions and limit in details. |
| Too many attachments | “A message can include up to 32 attachments.” Preserve existing entries and identify rejected items. |
| Corrupt/invalid content | “This file couldn't be read as an image. Try exporting it again.” |
| Clipboard reader missing | “Image paste isn't available on this machine. Use /attach, or install the named clipboard reader.” |
| Clipboard empty | “The clipboard contains no readable image or text.” |
| Clipboard access denied or timeout | State that reason; offer retry and file attachment. Do not call it an empty clipboard. |
| Upload failure | Entry remains failed: “Couldn't upload Image 2. Retry or remove it before sending.” |
| Owner offline | “Can't reach the session's computer. Your draft is still here.” Do not accept the message locally as if the owner accepted it. |
| Model unsupported | “This model doesn't accept images. Choose a model that does, or remove the images.” |
| Scope/session ended | Disable Send and uploads, preserve/copy the draft, and state the actual reason. |
| Storage full/quota | “There isn't enough attachment storage. Free space or change the runtime limit, then retry.” Never silently evict history. |
| Draft expired | “This image expired before it was sent. Attach it again.” Keep text and a labeled missing entry. |
| Acceptance unknown | “Checking whether this message was accepted…” Reconcile by original turn ID. |
| Accepted, provider failed | Show a failed turn with its images and the existing retry action. |
| History original unavailable | Show a labeled unavailable card; retries needing it fail explicitly. |

Backend errors use stable codes such as `attachment_invalid`, `attachment_too_large`,
`attachment_dimensions_exceeded`, `attachment_not_ready`, `attachment_expired`,
`attachment_not_authorized`, `attachment_owner_unavailable`, `attachment_quota`,
`model_images_unsupported`, and `attachment_integrity_failed`. Include an optional
safe attachment ID and `retryable` flag. Preserve existing outcome classifications
(`not_dispatched` versus unknown); a generic error string is not sufficient for
safe automatic retry. Avoid revealing whether an unauthorized attachment exists.

## 12. Performance and observability

Product targets, measured on documented reference hardware and network conditions:

- A pending image entry appears within 100 ms of receiving a paste/file event.
- A typical 2 MiB screenshot becomes Ready within 2 seconds on a local runtime;
  remote transfer time is measured and reported separately.
- Clipboard helpers, decoding, hashing, uploads, and preview retrieval never block
  keyboard input, streaming transcript processing, cancellation, or terminal resize.
- Preparation/upload state appears after 250 ms of outstanding work. Progress
  reflects acknowledged bytes; do not show fictitious progress during decoding.
- Upload queues, worker memory, disk reservations, browser object URLs, and TUI caches
  have enforced bounds and demonstrable cleanup.

Emit structured telemetry for preparation/upload duration, bytes, MIME, accepted
image count, validation failure code, cancellation, expired drafts, quota pressure,
and provider image rejection. Aggregate or scope identifiers according to existing
policy. No raw images, filenames from sensitive paths, user text, clipboard text,
or provider request bodies are telemetry fields.

## 13. Verification and acceptance plan

Use deterministic fixtures for protocol/runtime behavior and real OS/browser tests
for clipboard behavior. Synthetic paste events prove event handling, not that a
browser can read the operating system clipboard.

| Layer | Required coverage |
| --- | --- |
| Shared validation | Every supported format; mismatched extension/MIME; empty/truncated files; EXIF orientation; transparency; color profile; animation; huge dimensions; decompression bombs; source and normalized size boundaries. |
| Upload protocol | Exact chunk retry; conflicting offsets; disconnect before/after finish; finish response loss; unauthorized IDs; cross-session reuse; owner routing; small frame configuration; overdeclared/underdeclared sizes; cancellation and quotas. |
| Turn lifecycle | Text only, image only, multiple images, mixed legacy attachments, busy-to-follow-up retry, duplicate submit, changed envelope conflict, unknown dispatch, provider rejection, restart recovery, failed-turn retry, and queue recall. |
| Durability | Crash at each reservation/intent/acceptance boundary; expiry racing submission; deletion racing upload; pin/reference reconciliation; GC never removes accepted or unresolved input. |
| Model integration | Inspect actual adapter request content and order with a deterministic provider fixture; verify pixel digests, absence of local URLs/paths, image-only semantics, model pinning, and no silent image dropping. |
| Web component/LiveView | File input and upload writer, session switch during upload, removal during finish, text typed during acknowledgment, initial-message recovery, scope denial, no parser-cap bypass, authenticated preview reads. |
| Browser automation | Chromium, Firefox, WebKit engine tests for paste handler/file input/drop, mixed text/image, IME, disabled Send, dialog focus, narrow layout, reload/reconnect, and two-tab draft isolation. |
| Real web clipboard | Current stable Safari on macOS, Chrome/Chromium on macOS and Linux, Firefox on a supported desktop; paste screenshot and copied image, test denied optional clipboard read. Record OS/browser versions. |
| TUI unit/PTY | Helper errors and deadlines, text fallback even without image support, escaped/Unicode paths, ordered async completion, draft identity, empty-text images, keymap conflicts, bracketed paste, terminal restoration, screen reader output. |
| Real terminal matrix | macOS Terminal, iTerm2, a Kitty-compatible terminal, VS Code terminal, tmux, Linux Wayland and X11, plus a TUI running under SSH without desktop clipboard access. Record pixel versus placeholder results honestly. |
| Cross-client/fleet | Web sends → TUI replays; TUI sends → web replays; second client joining later; remote owner with different filesystem; owner outage; owner restart; different runtime capability versions. |
| Privacy and resource behavior | No workspace artifacts; no public URLs; encryption/inventory coverage; revoked auth; no filename escape injection; no body/byte logging; bounded memory/disk; staging cleanup after forced termination. |
| Packaging | Actual packaged macOS ARM64/x86-64 and Linux ARM64/x86-64 binaries include the decoder and run ingestion/normalization/cleanup smoke tests. Local tests do not establish hosted target results. |

Required end-to-end acceptance scenarios:

1. Copy a real screenshot, paste into an existing web session, type a question, and
   Send. Exactly one message contains the expected normalized image bytes. Refresh
   and open the session in TUI; both show its attachment.
2. Perform the same flow with TUI Ctrl+V and a supported local clipboard reader.
   Open in web; the image appears without relying on the sending client's disk.
3. Send two images without text from each client. Both images reach the provider in
   the displayed order; history has no fabricated user prompt.
4. Paste during an active turn. Queue the full message, change the session model,
   then verify the accepted turn retains its pinned destination and both images.
5. Remove an uploading image, switch sessions, and let its worker complete. Neither
   draft receives a resurrected or misplaced attachment, and staging is cleaned.
6. Lose the submit acknowledgment and reconnect. The accepted turn appears once,
   with the original images, and later typing remains untouched.
7. Point a local TUI/web endpoint at a session on another machine. Paste a screenshot
   absent from the remote workspace. The owner receives the bytes and stores them
   privately; neither repository gains `.ouroboros/images` files from the new path.
8. Start a new session with an image. Inject a failure after session creation and
   before first-send acknowledgment. Resume into the same session and one first turn.
9. Try unsupported, corrupt, too-large, and animated files. Each has a specific error;
   no partial text-only message or provider request escapes.
10. Exercise a text-only model and unknown model capability. Known unsupported input
    is blocked; a normal Send with unknown capability is recorded without claiming
    qualification. The full draft survives rejection.
11. Restart the runtime, replay older messages, compact history, and retry a failed
    image turn. Retained content remains addressable, authorized, and integrity checked.
12. Run without graphics support and through SSH without a clipboard reader. File
    attachment and descriptive history work; help accurately explains paste limits.

Live-provider qualification should use a small labeled fixture, such as a colored
shape plus a random short code, and record the returned interpretation alongside
adapter-level evidence that the image was included. Test representative configured
connection lanes with authorized accounts before claiming them supported. Unit tests,
an image rendered in chat, and a successful text response alone do not prove vision
delivery. Publish exactly which combinations were exercised.

## 14. Implementation sequence and ownership map

| Phase | Deliverable | Principal existing seams | Exit gate |
| --- | --- | --- | --- |
| 1. Contract and store | Versioned refs, authorization, bounded upload service, normalization helper, quotas, encryption, pin/recovery design. | `gateway/methods.ex`, `gateway/methods/contract.ex`, `gateway/config.ex`, `audit/content.ex`; new attachment service modules. | Deterministic ingestion and fault tests pass; no UI availability claim. |
| 2. Turn and history | Image-only schema, managed input resolution, provider parts, model capability admission, durable descriptors, retries/queue/replay. | `session/turn_request.ex`, `interactive/task/turns.ex`, `interactive/task.ex`, `provider/native/attachments.ex`, `provider/native/model/req_llm.ex`, `models.ex`, native context and replay modules. | A protocol client sends images to a fixture and both transcript projections reconstruct them. |
| 3. Web | Attachment tray, paste/file/drop, LiveView writer, previews, structured draft persistence, first-message integration. | `web/live/composer.ex`, `web/live/deck_live.ex`, `web/live/new_session_live.ex`, `web/live/cells.ex`, `web/router.ex`, `web/live_socket.ex`, `priv/static/web/app.js`, `app.css`. | Browser behavior, auth, draft race, and reload tests pass. |
| 4. TUI | Private source capture, upload transport, ref-based draft model, commands, cards/previews, recovery and remote ownership. | `tui/src/clipboard.rs`, `model.rs`, `ui/mod.rs`, `ui/app/session.rs`, `ui/sessions.rs`, `images.rs`, `keymap.rs`, `proto.rs`, transport modules. | PTY tests plus real local/remote clipboard scenarios pass. |
| 5. Qualification | Cross-client/fleet, packaged decoder, OS/browser matrix, representative live models, docs and release notes. | `test/browser`, web/gateway/native tests, `tui/tests`, release packaging/smoke scripts, `docs/PROTOCOL.md`, user documentation. | All required scenarios have recorded results and remaining unsupported combinations are explicit. |

Avoid gating a complete feature solely on a paste-handler test. The release unit is
ingestion through durable model input and replay in both surfaces. Intermediate work
may remain behind the advertised runtime capability until that complete path passes.

Update user help with exact paste shortcuts, `/paste-image`, `/attach` locality,
formats/limits, before-Send transfer behavior, draft expiry, remote/SSH limitations,
and model-support errors. Update protocol golden fixtures and compatibility tests
alongside the schema. Remove obsolete comments claiming attachments are necessarily
workspace paths or accepted-input events cannot describe images.

## 15. Definition of done

The feature is complete when R1–R10 and the required end-to-end scenarios pass for
the declared platform/model matrix; web and TUI show the same durable attachment
history; no new pasted-image files land in the project; image content survives
accepted-turn recovery; and failures never silently discard draft content or deliver
a partial message. Shipping claims distinguish source implementation, packaged
validation, and observed live-provider behavior.

This proposal chooses the first-release scope, default limits, ownership model,
error semantics, and compatibility behavior. Decoder dependency selection, exact
visual styling, and per-provider qualification entries are implementation work, not
unresolved product decisions or permission to reduce these guarantees.
