//! {{name}} — an ouroboros hook component, in the world `ouroboros:capability@0.1.0`.
//!
//! Build it:
//!
//! ```text
//! cargo build --release --target wasm32-wasip2
//! ```
//!
//! The component is `target/wasm32-wasip2/release/{{name_snake}}.wasm`. See README.md for how
//! to declare it in an `ouroboros.toml`.
//!
//! `#![no_std]` below is the one line of ceremony the SDK cannot own, and it is the one worth
//! keeping: `std` on this target imports thirteen `wasi:io`/`wasi:cli` interfaces the helper's
//! linker refuses, so a `std` build of this file would not instantiate at all. Everything else
//! — the allocator, the panic handler, the canonical ABI, the bindings — is behind
//! `export_hook!`.
//!
//! # What a hook may say, and what survives
//!
//! A hook component is admitted from a workspace nobody trusts, and the price is that it may
//! make a decision **stricter and never looser**. `Verdict::Deny`, `Verdict::Ask` and
//! `Verdict::Context` stand — context labelled on every line. `Verdict::Allow` is read as
//! silence and `Verdict::UpdatedInput` is dropped. `ouro wasm hook` prints both verdicts side
//! by side: what this component said, and what the node would act on.
//!
//! `Verdict::Silent` is the answer to every event this hook has no opinion about. It is not
//! `Allow`: silence is not consent, and an `Allow` would try to resolve an engine `ask` this
//! hook was never asked about.

#![no_std]

use ouroboros_guest::{
    export_hook, format, log, Describe, Hook, HookInput, String, ToString, Value, Verdict,
};

/// What one invocation of this hook was configured with. A hook instance is stood up, asked
/// once and dropped, so nothing here carries from one event to the next.
struct {{Name}} {
    ask_about: String,
}

impl Hook for {{Name}} {
    /// What this hook says about itself. `describe` is unread on the hook path — the node's
    /// seam asks for a verdict and nothing else — so this is documentation, and untrusted
    /// documentation at that. It is here because the same component may also be deployed as a
    /// capability, where it is captured at deploy.
    fn describe(name: &str, version: &str) -> Describe {
        Describe::new(name, version).summary("{{summary}}")
    }

    /// The `config = "…"` string beside `component =` in the `ouroboros.toml` that declared
    /// this hook, parsed. It is repository text like any other, so it is read defensively and
    /// never trusted to be there.
    fn init(config: Value) -> Result<Self, String> {
        let ask_about = config
            .get("ask_about")
            .and_then(Value::as_str)
            .unwrap_or("bash")
            .to_string();

        log("info", "{{name}} ready");

        Ok({{Name}} { ask_about })
    }

    /// One event, one verdict.
    ///
    /// As written this denies nothing and asks about one tool, which is the safe shape to
    /// start from: a hook that denies by accident is a repository that cannot run its own
    /// tools. Replace the body with the rule this hook exists to state.
    fn on(&mut self, input: HookInput) -> Result<Verdict, String> {
        // A hook is invoked for what its `matcher` matched and nothing else — but a component
        // that assumed so would be a component whose behaviour depends on somebody else's TOML.
        if !input.is("PreToolUse") {
            return Ok(Verdict::Silent);
        }

        let Some(tool) = input.tool_name.as_deref() else {
            return Ok(Verdict::Silent);
        };

        if tool.eq_ignore_ascii_case(&self.ask_about) {
            return Ok(Verdict::ask(format!("{{name}} asks about `{tool}`")));
        }

        Ok(Verdict::Silent)
    }
}

export_hook!({{Name}});
