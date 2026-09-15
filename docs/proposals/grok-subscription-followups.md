# Grok subscription follow-ups

**Status:** proposal, 2026-09-15. Source facts were read on `dev` at `7bea32f5`.
**Scope:** five defects in the native `grok:` subscription lane. Not a new product
surface. Settings already shows a Grok connection card; this document does not
reopen that work.

The lane's contract, already shipped and tested:

- `grok:<model>` reads the first-party OAuth entry in `~/.grok/auth.json` (or
  `OUROBOROS_GROK_AUTH_FILE`). It never copies or rotates the refresh token, and
  it never falls back to `XAI_API_KEY`.
- `xai:<model>` stays API-key billing. The two prefixes name different
  connections to the same Grok models.
- Window size, tool-schema protocol, and vision capability remap `grok:` to
  `xai:` metadata through `Ouroboros.Provider.GrokSubscription.api_model/1`.
  That remap is correct for *capability*. It is not a price.

This document decides how each remaining defect closes. One slice per defect,
smallest change that makes the stance explicit. Do not invent a `billing` wire
field, a Settings redesign, or a new credential store.

---

## 1. What exists today

**Transport.** `GrokSubscription.transport/2` (`lib/ouroboros/provider/grok_subscription.ex:121-159`)
opts in only on `"grok:" <> model`. Empty ids and ids containing `\r`, `\n`, or
`\0` return `{:error, {:grok_subscription, :invalid_model}}`. Credential failures
return `{:error, {:grok_subscription, reason}}` with
`reason in [:absent, :invalid, :expired, :unavailable]`. Admission happens
*before* `fetch/0` (`lib/ouroboros/provider/native/model/req_llm.ex:70-74`), so a
queued request sees a renewed or expired sign-in.

**Metadata remap.** `api_model("grok:" <> model)` yields `"xai:" <> model`.
Callers today:

| Call site | Remaps? | Why |
|---|---|---|
| `Context.Window.resolve/1` | yes | window size is a model fact |
| `Model.ReqLLM.build_tools/2` → `ToolSchema.prepare/2` | yes | Responses vs Chat Completions is a model fact |
| `Model.ReqLLM.vision?/1` | yes | image input is a model fact |
| `Cost.rates/1` via `LLMDB.model(model_spec)` | **no** | price is a connection fact |

**Catalogue.** `Ouroboros.Models.provider_models/1` concatenates
`subscription_models()` in front of the ranked `openai_codex` / `anthropic` /
`xai` rows, then `pin_configured/2`, then `Enum.take(models, 40)`
(`lib/ouroboros/models.ex:94-133`). `subscription_models/0` copies the xAI
catalogue entries whose ids are `"grok-4.6"` or `"grok-4.5"`, prefixes them
`grok:`, and sets `pricing: nil` plus `billing: :subscription`.

**Cost.** `Cost.payload/2` looks the model spec up in `llm_db` as-is
(`lib/ouroboros/provider/native/cost.ex:98-111`). A miss omits `cost_usd`; a
hit with rates emits a dollar figure. The native loop folds that figure into
`state.usage.cost` with `Map.get(payload, "cost_usd", 0.0)`
(`lib/ouroboros/provider/native/loop.ex:699-713`) and always writes
`"cost_usd" => Float.round(state.usage.cost, 6)` on `:turn_completed`
(`loop.ex:3752-3758`). Subagents start `cost: nil` and omit the key until a
priced payload arrives (`subagent.ex:523-527`, `loop.ex:3072-3075`). The
session fold treats a missing `cost_usd` as `nil`, never as zero
(`lib/ouroboros/interactive/state.ex:176-179`, `1387-1424`). TUI and web
render cost only when the number is present (`tui/src/ui/view.rs:712`,
`lib/ouroboros/web/live/cells.ex:619`).

**Errors.** `error_summary/1` special-cases
`{:grok_subscription, reason}` only when
`reason in [:absent, :invalid, :expired, :unavailable]`
(`req_llm.ex:127-136`). `:invalid_model` falls through to
`category=unknown … diagnostic=model request failed`. Web maps
`category=credentials` to a Settings prompt
(`lib/ouroboros/web/live/cells.ex:437-438`); `category=unknown` is a generic
failure.

**Credential file.** `read_private/1` `lstat`s, rejects non-regular files and
group/other bits, then `File.open/3` on the same path
(`grok_subscription.ex:64-86`). The existing test plants a symlink *before*
`fetch/0` and expects `:invalid`
(`test/provider/grok_subscription_test.exs:80-88`). `XAIKey` and
`AnthropicKey` `lstat` before and after `File.read/1` and compare inode /
device / uid (`xai_key.ex:96-111`, `anthropic_key.ex:250-265`).
`OpenAIAuth.read_credentials/1` still uses `File.stat/1` (follows links) —
that is a sibling of this work, not in scope.

**Dead field.** `billing: :subscription` is set in `subscription_models/0`
and asserted in one test (`test/provider/grok_subscription_test.exs:274`).
`runtime.models` has an open envelope (`docs/PROTOCOL.md` `runtime.models`).
The TUI `ModelEntry` has no `billing` field and does not deny unknown keys
(`tui/src/model.rs:1396-1419`). Web picker `model_detail/2` never reads it
(`new_session.ex:481-498`). Nothing else in `lib/` or `tui/` matches the atom
or the JSON key.

---

## 2. Product stance (decided here)

1. **A `grok:` turn is unpriced.** Token counts, window, and meter still
   report. `cost_usd` is absent. A footer that showed xAI list prices on a
   SuperGrok turn would be an invoice-shaped lie: the operator is not being
   billed per token by that connection. `xai:` turns stay priced from
   `llm_db` as today.
2. **The picker bound is a bound on what a person scans, not a tax the
   subscription lane may levy.** `grok-4.5` and `grok-4.6` must remain
   selectable. They must not displace Astra, a configured default, or the
   newest Anthropic / OpenAI rows the cap was sized for.
3. **`billing` is not product surface.** Do not put it on the wire. Do not
   teach the TUI or the web picker to read it. The connection is already
   named by the `grok:` prefix and by the Grok subscription group heading
   (`new_session.ex:434`).
4. **A refused `grok:` model id is a request error, not a credential
   error.** Telling the operator to run `grok login` for `"grok:"` or
   `"grok:grok-4.6\n"` is the wrong diagnosis.
5. **Reading `~/.grok/auth.json` must not follow a path that was a regular
   file at `lstat` and a symlink at open.** Same class of check the
   node-owned key files already do. Do not copy those files into the
   Ouroboros data directory; Grok owns the inode.

---

## 3. Slices

Implement in this order. Each slice is independently mergeable and has its
own tests. Do not combine 3.1 and 3.4 in one commit: one is a pricing
contract, the other is a catalogue bound.

### 3.1 Cost: subscription ⇒ unpriced, on purpose

**Change `Cost.rates/1` (or `cost_usd/5`) so a `grok:` spec never consults
`llm_db`.** Return `nil` before `LLMDB.model/1`. Do not remap through
`api_model/1`. Do not look up `"xai:" <> rest`. An unknown `grok:` id is
still unpriced; that is the same answer as a known one, and that is the
point.

Leave `Window.resolve/1`, `ToolSchema.prepare/2`, and `vision?/1` on
`api_model/1`. Those are capability lookups.

**Loop fold.** `record_usage/1` adding `Map.get(payload, "cost_usd", 0.0)`
into `state.usage.cost` is already correct for an omitted key: the running
total stays `0.0`. `:turn_completed` then emits `"cost_usd" => 0.0`. That
zero is a running total of *reported* prices, not a claim that the turn was
free, but it is the same zero an unpriced `scripted:` turn already emits
today. **Do not change the terminator in this slice.** A parent-loop `cost:
nil` like the subagent path is a separate, pre-existing inconsistency
(`loop.ex:283` vs `subagent.ex:527`) and is out of scope. The session fold
already prefers `:usage` token counts and only sums `cost_usd` when the key
is present; an omitted key on `:usage` keeps `usage.cost_usd` `nil`
(`interactive/state.ex:1409-1424`, `test/interactive_usage_test.exs:41`).
That is the number the footer reads.

**Tests that must go red first**

- Extend `test/provider/native/cost_test.exs`:
  `Cost.payload(%{input_tokens: 100, output_tokens: 10}, "grok:grok-4.6")`
  has no `"cost_usd"` key, and the same for `"grok:does-not-exist"`.
- The regression that pins the stance against a future `llm_db` `grok`
  provider: if `LLMDB.model("grok:grok-4.6")` were to start succeeding,
  `Cost.cost_usd("grok:grok-4.6", 1_000_000, 0, 0, 0)` is still `nil`.
  Implement this without stubbing if the snapshot has no such row — assert
  both `LLMDB.model("grok:grok-4.6")` is not `{:ok, _}` *and*
  `Cost.cost_usd/5` is `nil`. Add a comment that the `Cost` clause, not the
  miss, is the contract; a later snapshot bump must not be allowed to
  start quoting API list prices.
- Keep `test/provider/grok_subscription_test.exs` "catalogue and context
  preserve metadata…" but drop the accidental-miss framing. After this
  slice it is asserting the `Cost` clause.
- Contrast: `Cost.payload(..., "xai:grok-4.6")` still prices when `llm_db`
  has rates for that id. If the snapshot has no rates, `cost_usd` is
  absent for `xai:` too — that is the existing unknown-model contract,
  unchanged.

**Must not change**

- `api_model/1`.
- Window equality between `grok:grok-4.6` and `xai:grok-4.6`.
- `xai:` pricing.
- Footer / TUI decoding of `cost_usd`.

**Docs.** One sentence in `Ouroboros.Provider.Native.Cost`'s moduledoc:
`grok:` is unpriced because it is a subscription connection, not because
`llm_db` lacks the id. Update `lib/ouroboros/models.ex` moduledoc only if
it currently implies `llm_db` is the sole reason a native model has no
price — it already says "Not pricing this runtime charges or verifies"
(`models.ex:23-26`); leave it unless a sentence now contradicts 3.1.

### 3.2 Catalogue cap: pin, don't prepend-and-hope

**Today.** `subscription_models()` is prepended, then `pin_configured/2`,
then `take(40)`. Two subscription rows always occupy the first two slots
of the 40 (or slots 2–3 when a configured id is pinned in front).
`total` is `length(models)` *before* the take, so it already counts the
prepend. There is no test that Astra, or a given Anthropic id, still
survives once those two rows exist. `test/models_test.exs` "Astra is
discoverable…" happens to pass on the current snapshot; a snapshot that
grows the OpenAI/Anthropic head would drop Astra two models sooner than
the cap's authors sized for.

**Change.** Treat subscription rows the same way `pin_configured/2` treats
the configured default: they are reserved slots *inside* the 40, not a tax
on the ranked list.

Concretely, in `provider_models/1`:

1. Build the ranked lane list as today (no prepend).
2. `pin_configured/2` as today.
3. Build `subscription_models()` as today (`pricing: nil`, no `billing`
   key — see 3.3).
4. Drop any ranked row whose `id` is already in the subscription list
   (there should be none: prefixes differ).
5. Take `@max_models - length(subscription)` from the ranked list.
6. Concatenate `subscription ++ ranked_taken`. If the configured id is a
   `grok:` id, it is already in `subscription` and `pin_configured/2` has
   moved it to the head of the ranked list as well — deduplicate so it
   appears once, at the head of the whole answer.

Result:

- `grok:grok-4.5` and `grok:grok-4.6` are always in `models` when the xAI
  snapshot still carries them.
- The remaining 38 slots (or 39/40 if a subscription id is missing from
  the snapshot) are the same ranked lane models the cap was for.
- `total` remains `length(ranked_full ++ subscription)` after
  dedup, so a client can still see that the bound truncated the ranked
  list.
- Order inside the subscription block stays newest-first as
  `catalog_models(:xai)` already sorts.

Do not grow `@max_models`. Do not special-case the web picker: it already
groups `grok:` under "Grok subscription · direct via Ouroboros"
(`new_session.ex:434`) and sorts groups alphabetically, so picker
*placement* on the new-session form is a group heading, not list order.
The TUI / `runtime.models` consumers that walk `models` in order will see
subscription ids first; that is acceptable and matches "newest first, plus
the connections this node always offers".

**Tests that must go red first**

- In `test/models_test.exs`:
  - With the default configured model *not* a `grok:` id, the native row
    contains both `grok:grok-4.6` and `grok:grok-4.5`, contains
    `openai_codex:gpt-6-astra`, and `length(models) == 40`.
  - `total >= 40` and `total == length(models)` only when the combined
    ranked list plus subscription fits; otherwise `total > length(models)`.
  - Pinning a missing configured id still yields 40 rows (the pin plus 39
    others, subscription included). Today `length(row.models) == 40` is
    already asserted for a missing configured id
    (`test/models_test.exs:34`); keep it, and assert the two `grok:` ids
    are among those 40.
  - A configured `grok:grok-4.6` still appears once, first, with
    `configured: true` and `pricing: nil`.
- Keep the grok subscription test's catalogue assertions, minus
  `billing: :subscription` (3.3).

**Must not change**

- `@max_models`.
- Lane ranking (release date desc, then id, then prefix).
- `find_model/2` for `grok:` (already looks up `:xai` by bare id).
- Web group labels.

### 3.3 Delete `billing: :subscription`

**Change.** Stop putting `:billing` on the model map. `pricing: nil` is
the catalogue signal; the `grok:` prefix is the connection signal. After
3.1, `Cost` does not need a catalogue flag either.

`Wire.to_json/1` would have encoded the atom as the string `"subscription"`
on `runtime.models` today. Removing the key is backwards-compatible: the
envelope is open, clients ignore unnamed keys, and no client reads this
one.

**Tests.** Replace
`assert %{id: "grok:grok-4.6", pricing: nil, billing: :subscription}`
with `assert %{id: "grok:grok-4.6", pricing: nil}` plus
`refute Map.has_key?(hd(row.models), :billing)`. Add the same refute to
the models catalogue test in 3.2 so a later contributor cannot put the
key back as decoration.

**Must not change.** Do not add `billing` to `tui/src/model.rs`
`ModelEntry`. Do not document a billing field in PROTOCOL.

### 3.4 Error: `:invalid_model` is not a sign-in problem

**Change.** A second `error_summary/1` clause:

```elixir
defp error_summary({:grok_subscription, :invalid_model}) do
  fields(
    :unknown,
    nil,
    nil,
    false,
    "Grok subscription model id is invalid"
  )
end
```

Keep the existing clause for `:absent | :invalid | :expired | :unavailable`
on `category=credentials` with "run grok login". Do not classify
`:invalid_model` as `credentials`: the web surface would tell the operator
to open Settings for a syntactically bad id.

Do not interpolate the rejected model id into the diagnostic. Model ids
are operator-controlled and can be large; the existing formatter already
refuses to echo provider-controlled strings
(`req_llm.ex:191-200`, `test/provider/native/req_llm_test.exs:220-246`).

`transport/2` stays as it is. The hole is only in the formatter.

**Tests that must go red first**

- In `test/provider/grok_subscription_test.exs` (or `req_llm_test.exs`):
  - `GrokSubscription.transport("grok:", [])` and
    `GrokSubscription.transport("grok:grok-4.6\n", [])` return
    `{:error, {:grok_subscription, :invalid_model}}` without reading a
    credential file (no `XAI_API_KEY` fallback either).
  - `DirectModel.format_error({:grok_subscription, :invalid_model})`
    contains `category=unknown`, contains `Grok subscription model id is
    invalid`, does not contain `run grok login`, does not contain
    `category=credentials`.
  - Existing `:expired` assertion (`format_error(…) =~ "run grok login"`)
    stays.

**Must not change.** Credential error copy. Web `cells.ex` category map
(credentials still means "check Settings").

### 3.5 TOCTOU: same inode from `lstat` to read

**Threat.** `read_private/1` accepts a regular mode-0600 file, then
`File.open/3` follows the path. Between those calls a local attacker who
can replace `~/.grok/auth.json` with a symlink can make Ouroboros read
whichever target the link names. The current symlink test does not cover
this: it plants the link *before* `lstat`, which already returns
`type: :symlink` and `:invalid`.

This is the same class `XAIKey` / `AnthropicKey` close for node-owned
files, with one difference: Grok owns `~/.grok/auth.json`. Ouroboros must
not copy, chown, or move it. Owner-uid equality against
`DataDir.current_uid!()` is in scope if cheap; refusing a file the
runtime user does not own is correct. Do not require mode `0o600`
exactly — the existing check is `band(mode, 0o077) == 0`, which allows
`0400` as well as `0600`, and Grok's own writes may use either.

**Change `read_private/1` / `bounded_read/1`:**

1. `lstat` the path (already). Reject non-regular, oversize, and
   group/other-readable as today.
2. Open without following the final component. On Unix this is
   `:file.open(path, [:read, :raw, :binary])` after the `lstat`, then
   `:file.read_file_info(io, [{:time, :posix}])` on the *fd*, then
   compare `inode`, `major_device`, `uid`, `size` (and `type == :regular`)
   with the `lstat`. If they differ, `{:error, :invalid}` (or
   `:unavailable` — pick one and test it; `:invalid` matches "this is not
   the credential file we inspected").
3. Read at most `@max_bytes` from that fd. `lstat` again after the read
   and compare inode / device / size. A replace during the read is
   `:invalid`.
4. Do not call `File.open/3` / `File.read/1` on the path after the first
   `lstat`; those follow a replaced symlink.

A portable fallback if the fd-info compare is awkward in Elixir: open,
`lstat` immediately after open, compare with the pre-open `lstat`, read,
`lstat` again. That still loses to a same-inode truncate-and-rewrite, but
it closes the symlink-replace window the finding named. Prefer the fd
compare; it is what `Workspace.Deliveries.read_file/4` already does
(`deliveries.ex:152-189`).

`fetch/0`'s `rescue → :unavailable` stays the backstop for `lstat`
raising.

**Tests that must go red first**

- Keep "refuses public and symlinked credential files".
- Add: write a valid credential at `path`, `lstat` would accept it, then
  replace `path` with a symlink to a *different* regular 0600 file that
  contains a canary token, in the window the old code would follow.
  Drive this by extracting the open/read into a function the test can
  hook, **or** by a deterministic helper that calls the read with a
  pre-captured `File.Stat` whose path has since been replaced. The second
  form is enough: expose (or test via `fetch/0` after) a function
  `read_private/1` cannot be split around, so instead:

  A pragmatic test that still goes red on the old code:

  1. Write a valid credential at `path`.
  2. In the test process, `File.rename(path, path <> ".orig")`,
     `File.ln_s!(path <> ".orig", path)` is already covered.
  3. The TOCTOU case: write valid bytes at `innocent`, write canary bytes
     at `secret` (both 0600 regular), `File.rename(innocent, path)` is not
     the window. The window is `lstat(path)` then `open(path)`.

  Because we cannot pause between those calls from the test without a
  seam, add a small internal function:

  ```elixir
  defp bounded_read(path, %File.Stat{} = expected) do
    # open, fd-stat, compare to expected, read, lstat, compare
  end
  ```

  and test `bounded_read(path, lstat_of_regular_file)` after `path` has
  been replaced with a symlink to a canary file. The public `fetch/0`
  uses `bounded_read(path, stat)` with the `lstat` it just took. The test
  module can call the seam through a `@doc false` `read_matching/2` if
  `bounded_read/2` stays private — prefer testing via
  `GrokSubscription.fetch/0` plus the seam only if fetch cannot express
  the race. A `@doc false` `read_private_with_stat/2` used solely by the
  test is acceptable; do not make it part of the provider behaviour.

- The canary token must not appear in `fetch/0`'s ok-tuple after the
  replace. `inspect(status())` must not contain it either (existing
  secret-canary discipline).
- Replacing with a directory, a world-readable file, or a missing path
  during the window is `:invalid` or `:absent` / `:unavailable` as the
  post-open `lstat` decides — assert the canary is not returned, not a
  particular atom, unless the atom is already part of the public
  `fetch/0` contract.

**Must not change**

- Path resolution (`OUROBOROS_GROK_AUTH_FILE`, `:grok_auth_file`, default
  `~/.grok/auth.json`).
- Token validation (`auth_mode`, issuer, client id, expiry skew).
- Never writing the file.
- `OpenAIAuth.read_credentials/1` (follows links via `File.stat/1`). Note
  it in the implementer report as a sibling, do not fix it here.

---

## 4. Out of scope

- Settings Grok card, logos, TUI Settings refresh — already landed after
  the review that named items 2–6.
- Copying `~/.grok/auth.json` into the Ouroboros data directory.
- Refreshing Grok OAuth tokens. Grok owns rotation; expired ⇒
  `grok login`.
- Teaching `Cost` to remap `grok:` to `xai:` prices "just in case".
- A `billing` field on `runtime.models`, TUI `ModelEntry`, or PROTOCOL.
- Raising `@max_models`.
- Changing `:turn_completed`'s always-present `cost_usd` zero, or
  aligning the parent loop's `cost: 0.0` with the subagent `cost: nil`.
- `OpenAIAuth` symlink following.
- New subscription model ids beyond the two `subscription_models/0`
  already lists. Adding `grok-4.7` later is a one-line filter change and
  a catalogue test update, not this work.

---

## 5. Implementation notes

- All five slices live under `lib/ouroboros/provider/`,
  `lib/ouroboros/models.ex`, and their tests. None of them belong in
  `lib/ouroboros/control/`, `upgrade/`, or `storage/`.
- Tests that write application env (`:native_model`, `:grok_auth_file`)
  stay `async: false`. `Cost` tests that only call `Cost.payload/2` may
  stay `async: true`.
- Do not stub `LLMDB` globally. A snapshot bump that adds a `grok`
  provider is exactly the event 3.1 is defending against; the test should
  still pass.
- Formatter diagnostics stay bounded (`byte_size <= 1_024`) and must not
  echo the rejected model id or any credential path.
- `mix test test/provider/native/cost_test.exs test/provider/grok_subscription_test.exs test/models_test.exs`
  is the slice 3.1–3.4 gate. Slice 3.5 is the grok subscription file plus
  whatever `@doc false` seam it adds. Redirect and grep
  `Result:` / `Failed:` as `docs/self/briefs/implementer.md` requires.
- Docs: update a sentence only where it would be false after the change.
  Candidates are the `Cost` moduledoc (3.1) and the `subscription_models/0`
  comment (3.2, 3.3). Do not add a new document beyond this one.

---

## 6. Acceptance

The work is done when all of the following are true, each named by a test:

| Slice | Test proves |
|---|---|
| 3.1 | `Cost.payload/2` for `grok:grok-4.6` and `grok:does-not-exist` omits `cost_usd`; `xai:grok-4.6` still prices when `llm_db` has rates; `Window.resolve/1` still equalizes the two prefixes |
| 3.2 | native `models` length is 40, contains both `grok:` ids and `openai_codex:gpt-6-astra`; a configured `grok:grok-4.6` appears once at the head; `total` still reports the unbound count |
| 3.3 | no model map in `Models.list()` has a `:billing` key |
| 3.4 | `transport("grok:", [])` is `{:grok_subscription, :invalid_model}`; `format_error/1` of that tuple is `category=unknown` and does not mention `grok login`; `:expired` still does |
| 3.5 | `bounded_read/2` (or the public seam) against a pre-captured regular `File.Stat` whose path is now a symlink to a canary file returns an error and not the canary; the existing pre-planted symlink test still returns `:invalid` |

UNVERIFIED until an implementer runs those files: live `grok login` against
xAI, and whether Grok's client writes `0600` or `0400`. The mode check
already accepts both (`band(mode, 0o077) == 0`); do not tighten it in 3.5.
