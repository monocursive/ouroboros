//! D4. `ouro mcp add` / `remove` / `list`, at the level of the bytes they write and print.
//!
//! The file assertions are byte-exact on purpose. This command edits a file another
//! program — the Elixir loader, and Claude Code itself — parses, so "it round-trips
//! through our own reader" is not the property that matters; "these exact bytes are on
//! disk" is.
//!
//! The three honesty properties this file is here to hold:
//!
//! * **An environment value is never printed back.** `add` is handed one and every line it
//!   writes afterwards is searched for it.
//! * **A definition is never silently replaced.** A name already present with different
//!   bytes is refused, and `--force` is the only way past.
//! * **A `url` entry is written and its fate is stated.** The file is valid; this runtime
//!   speaks stdio only and the command says so rather than letting an operator discover it
//!   from an empty tool list.

mod support;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde_json::json;

use ouro::mcp_cli::{self, Definition, Scope};
use ouro::model::McpList;

use support::fixture;

/// A scratch directory of this test's own. Never the operator's real config root: these
/// tests write files, and `mcp_cli::path` is exercised separately against a fake HOME.
fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ouro-mcp-cli-{}-{name}", std::process::id()));

    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("a scratch directory");

    root
}

fn add(path: &Path, definition: &Definition, force: bool) -> (String, anyhow::Result<()>) {
    let mut out = Vec::new();
    // `check: false` everywhere but the one test about it: whether `/bin/cat` exists is
    // not what the other tests are measuring.
    let result = mcp_cli::add(path, Scope::User, definition, force, false, &mut out);

    (String::from_utf8(out).expect("utf-8 output"), result)
}

fn stdio(name: &str, command: &str) -> Definition {
    Definition {
        name: name.to_string(),
        command: Some(command.to_string()),
        ..Definition::default()
    }
}

// ----- add ---------------------------------------------------------------------------

/// The exact bytes, because another program parses them.
#[test]
fn add_writes_the_claude_compatible_document_byte_for_byte() {
    let path = scratch("write").join("mcp.json");

    let definition = Definition {
        name: "fake".into(),
        command: Some("/usr/bin/fake-mcp".into()),
        args: vec!["--stdio".into(), "--verbose".into()],
        env: vec!["TOKEN=s3cr3t".into()],
        ..Definition::default()
    };

    let (printed, result) = add(&path, &definition, false);
    result.expect("the entry is written");

    assert_eq!(
        fs::read_to_string(&path).expect("the file"),
        concat!(
            "{\n",
            "  \"mcpServers\": {\n",
            "    \"fake\": {\n",
            "      \"args\": [\n",
            "        \"--stdio\",\n",
            "        \"--verbose\"\n",
            "      ],\n",
            "      \"command\": \"/usr/bin/fake-mcp\",\n",
            "      \"env\": {\n",
            "        \"TOKEN\": \"s3cr3t\"\n",
            "      }\n",
            "    }\n",
            "  }\n",
            "}\n",
        ),
    );

    // The one thing the printed output must not contain.
    assert!(
        !printed.contains("s3cr3t"),
        "an environment value is never printed back:\n{printed}"
    );
    assert!(
        printed.contains("1 environment variable(s)"),
        "the count is, because it is the whole of what may be said\n{printed}"
    );
}

/// The directory is 0700 and the file is 0600, both created by this command.
#[test]
fn add_creates_a_private_directory_and_a_private_file() {
    let root = scratch("modes");
    let directory = root.join("nested").join("ouroboros");
    let path = directory.join("mcp.json");

    let (_printed, result) = add(&path, &stdio("fake", "/bin/cat"), false);
    result.expect("the entry is written");

    assert_eq!(
        fs::metadata(&directory).expect("the directory").mode() & 0o777,
        0o700,
        "the directory this command created is private to its operator"
    );
    assert_eq!(
        fs::metadata(&path).expect("the file").mode() & 0o777,
        0o600,
        "and so is the file, which may carry a token"
    );
}

/// A second server joins the first rather than replacing the document.
#[test]
fn add_merges_into_an_existing_document() {
    let path = scratch("merge").join("mcp.json");

    add(&path, &stdio("first", "/bin/one"), false)
        .1
        .expect("the first entry");
    add(&path, &stdio("second", "/bin/two"), false)
        .1
        .expect("the second entry");

    let document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("the file")).expect("valid JSON");

    assert_eq!(
        document,
        json!({
            "mcpServers": {
                "first": {"command": "/bin/one"},
                "second": {"command": "/bin/two"},
            }
        }),
    );
}

/// A name already present with different bytes is refused; `--force` replaces it.
#[test]
fn add_refuses_to_clobber_a_different_definition_without_force() {
    let path = scratch("clobber").join("mcp.json");

    add(&path, &stdio("fake", "/bin/one"), false)
        .1
        .expect("the first entry");

    let (_printed, refused) = add(&path, &stdio("fake", "/bin/two"), false);
    let refusal = refused.expect_err("a different definition under the same name is refused");

    assert!(
        refusal.to_string().contains("--force"),
        "the refusal names the way to say it on purpose: {refusal}"
    );

    // Refused means unchanged, not partially applied.
    assert!(
        fs::read_to_string(&path)
            .expect("the file")
            .contains("/bin/one"),
        "a refused add leaves the file as it was"
    );

    let (printed, forced) = add(&path, &stdio("fake", "/bin/two"), true);
    forced.expect("--force replaces it");

    assert!(fs::read_to_string(&path)
        .expect("the file")
        .contains("/bin/two"));
    assert!(printed.contains("wrote fake"), "{printed}");
}

/// Writing the identical definition twice is not a clobber and is not an error.
#[test]
fn add_is_idempotent_for_an_identical_definition() {
    let path = scratch("idempotent").join("mcp.json");

    add(&path, &stdio("fake", "/bin/one"), false)
        .1
        .expect("the first entry");

    let before = fs::read_to_string(&path).expect("the file");

    let (printed, again) = add(&path, &stdio("fake", "/bin/one"), false);
    again.expect("an identical definition is not a conflict");

    assert_eq!(fs::read_to_string(&path).expect("the file"), before);
    assert!(printed.contains("nothing to do"), "{printed}");
}

/// A `url` entry is written, and the command says what the runtime will do with it.
#[test]
fn add_accepts_a_url_entry_and_says_the_runtime_will_refuse_it() {
    let path = scratch("url").join("mcp.json");

    let definition = Definition {
        name: "remote".into(),
        url: Some("https://example.invalid/mcp".into()),
        ..Definition::default()
    };

    let (printed, result) = add(&path, &definition, false);
    result.expect("the entry is written");

    let document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("the file")).expect("valid JSON");

    assert_eq!(
        document["mcpServers"]["remote"],
        json!({"url": "https://example.invalid/mcp"}),
    );

    assert!(
        printed.contains("unsupported_transport"),
        "the command names the refusal the runtime will give: {printed}"
    );
    assert!(printed.contains("stdio"), "{printed}");
}

/// The loader's own name rule, refused where the operator types it rather than three
/// commands later in a status listing.
#[test]
fn add_refuses_a_name_the_loader_would_refuse() {
    let path = scratch("names").join("mcp.json");

    for name in ["", "has space", "has__underscores", "café", &"x".repeat(65)] {
        let (_printed, result) = add(&path, &stdio(name, "/bin/cat"), false);

        assert!(
            result.is_err(),
            "{name:?} is not a usable server name and must be refused"
        );
    }

    assert!(!path.exists(), "a refused name writes no file at all");

    // And the ones that are fine.
    for name in ["fake", "my-server", "my_server", "a1"] {
        add(&path, &stdio(name, "/bin/cat"), false)
            .1
            .unwrap_or_else(|error| panic!("{name:?} is a usable name: {error}"));
    }
}

/// `--env` without an `=` is refused, and the refusal does not quote a value.
#[test]
fn add_refuses_an_env_pair_it_cannot_split() {
    let path = scratch("env").join("mcp.json");

    let definition = Definition {
        name: "fake".into(),
        command: Some("/bin/cat".into()),
        env: vec!["JUST_A_NAME".into()],
        ..Definition::default()
    };

    let (_printed, result) = add(&path, &definition, false);
    let refusal = result.expect_err("KEY=VALUE is the shape").to_string();

    assert!(refusal.contains("KEY=VALUE"), "{refusal}");
}

/// A value containing `=` survives: the split is on the first one only.
#[test]
fn an_env_value_may_contain_an_equals_sign() {
    let path = scratch("env-equals").join("mcp.json");

    let definition = Definition {
        name: "fake".into(),
        command: Some("/bin/cat".into()),
        env: vec!["TOKEN=a=b=c".into()],
        ..Definition::default()
    };

    let (printed, result) = add(&path, &definition, false);
    result.expect("the entry is written");

    let document: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("the file")).expect("valid JSON");

    assert_eq!(document["mcpServers"]["fake"]["env"]["TOKEN"], "a=b=c");
    assert!(!printed.contains("a=b=c"), "{printed}");
}

/// A definition with neither transport is refused before anything is written.
#[test]
fn add_refuses_a_definition_with_no_transport() {
    let path = scratch("no-transport").join("mcp.json");

    let definition = Definition {
        name: "fake".into(),
        ..Definition::default()
    };

    let (_printed, result) = add(&path, &definition, false);
    assert!(result.is_err());
    assert!(!path.exists());
}

/// The PATH check warns and writes; it never refuses.
#[test]
fn a_command_that_does_not_resolve_is_a_warning_and_not_a_refusal() {
    let path = scratch("check").join("mcp.json");

    let mut out = Vec::new();
    let definition = stdio("fake", "/nonexistent/definitely-not-here");

    mcp_cli::add(&path, Scope::User, &definition, false, true, &mut out)
        .expect("an unresolvable command is written anyway");

    let printed = String::from_utf8(out).expect("utf-8");

    assert!(printed.contains("warning"), "{printed}");
    assert!(
        path.exists(),
        "the entry is written: the file may be for a session that runs elsewhere"
    );
}

/// A workspace scope says the file is only read for a workspace the runtime trusts.
#[test]
fn a_workspace_scope_says_the_file_needs_trust() {
    let path = scratch("trust").join(".ouroboros").join("mcp.json");

    let mut out = Vec::new();
    mcp_cli::add(
        &path,
        Scope::Workspace,
        &stdio("fake", "/bin/cat"),
        false,
        false,
        &mut out,
    )
    .expect("the entry is written");

    let printed = String::from_utf8(out).expect("utf-8");
    assert!(printed.contains("trust"), "{printed}");
}

/// A file that is not a JSON object is reported, never replaced.
#[test]
fn add_refuses_to_replace_a_file_it_cannot_read() {
    let root = scratch("garbage");
    let path = root.join("mcp.json");

    fs::write(&path, "this is not json\n").expect("a garbage file");

    let (_printed, result) = add(&path, &stdio("fake", "/bin/cat"), false);
    assert!(result.is_err(), "a malformed mcp.json is reported");

    assert_eq!(
        fs::read_to_string(&path).expect("the file"),
        "this is not json\n",
        "and left exactly as it was"
    );
}

// ----- remove ------------------------------------------------------------------------

#[test]
fn remove_takes_one_entry_and_leaves_the_rest() {
    let path = scratch("remove").join("mcp.json");

    add(&path, &stdio("first", "/bin/one"), false)
        .1
        .expect("one");
    add(&path, &stdio("second", "/bin/two"), false)
        .1
        .expect("two");

    let mut out = Vec::new();
    mcp_cli::remove(&path, "first", &mut out).expect("the removal");

    assert_eq!(
        fs::read_to_string(&path).expect("the file"),
        concat!(
            "{\n",
            "  \"mcpServers\": {\n",
            "    \"second\": {\n",
            "      \"command\": \"/bin/two\"\n",
            "    }\n",
            "  }\n",
            "}\n",
        ),
    );

    let printed = String::from_utf8(out).expect("utf-8");
    assert!(printed.contains("removed first"), "{printed}");
}

/// Removing the last entry leaves an empty map, which says "this scope declares nothing"
/// — a different statement from a file that was never written.
#[test]
fn remove_leaves_an_empty_map_rather_than_dropping_the_key() {
    let path = scratch("remove-last").join("mcp.json");

    add(&path, &stdio("only", "/bin/one"), false)
        .1
        .expect("one");

    let mut out = Vec::new();
    mcp_cli::remove(&path, "only", &mut out).expect("the removal");

    assert_eq!(
        fs::read_to_string(&path).expect("the file"),
        "{\n  \"mcpServers\": {}\n}\n",
    );
}

/// Removing something that is not there is said, not an error.
#[test]
fn remove_of_an_absent_name_says_so() {
    let path = scratch("remove-absent").join("mcp.json");

    let mut out = Vec::new();
    mcp_cli::remove(&path, "ghost", &mut out).expect("not an error");

    let printed = String::from_utf8(out).expect("utf-8");
    assert!(printed.contains("no server named ghost"), "{printed}");
}

// ----- paths -------------------------------------------------------------------------

/// `--scope workspace` puts the file where the runtime's loader looks for it.
#[test]
fn a_workspace_path_is_the_one_the_loader_reads() {
    let root = PathBuf::from("/srv/repo");

    assert_eq!(
        mcp_cli::path(Scope::Workspace, Some(&root)).expect("a path"),
        PathBuf::from("/srv/repo/.ouroboros/mcp.json"),
    );

    assert!(
        mcp_cli::path(Scope::Workspace, None).is_err(),
        "a workspace scope with no workspace is refused rather than guessed at"
    );
}

// ----- list --------------------------------------------------------------------------

/// `mcp.list` params: both keys optional, and `workspace` is what makes the answer
/// complete.
#[test]
fn the_list_params_carry_only_what_was_asked_for() {
    assert_eq!(mcp_cli::list_params(None, None), json!({}));

    assert_eq!(
        mcp_cli::list_params(Some("ouroboros@golden"), Some(Path::new("/srv/repo"))),
        json!({"node": "ouroboros@golden", "workspace": "/srv/repo"}),
    );

    // A blank node is absent, not an empty string the gateway would refuse.
    assert_eq!(mcp_cli::list_params(Some("  "), None), json!({}));
}

/// The plain page, against the golden fixture the runtime is pinned to.
#[test]
fn the_plain_page_states_every_server_and_every_refusal() {
    let list = McpList::decode(&fixture("mcp_list_result")["result"]);
    let page = mcp_cli::render(&list);

    // The three states, told apart.
    assert!(page.contains("fake  ready"), "{page}");
    assert!(page.contains("flaky  broken"), "{page}");
    assert!(page.contains("notes  configured"), "{page}");

    // A broken server says why.
    assert!(page.contains("broken: {:restart_limit"), "{page}");

    // A configured server is not reported as advertising zero tools: it has not started.
    assert!(
        !page.contains("notes  configured · workspace · 0 tool(s)"),
        "{page}"
    );

    // The refusal, with its typed reason and the runtime's sentence.
    assert!(page.contains("REFUSED  1"), "{page}");
    assert!(page.contains("remote  unsupported_transport"), "{page}");
    assert!(page.contains("HTTP/SSE"), "{page}");

    // The environment is a count and nothing else.
    assert!(page.contains("1 env var(s)"), "{page}");
    assert!(!page.to_lowercase().contains("token="), "{page}");
}

/// `--json` is the runtime's own answer, not a projection this client would have to keep
/// in step by hand.
#[test]
fn the_json_output_is_the_runtimes_own_bytes() {
    let answer = fixture("mcp_list_result")["result"].clone();
    let rendered = mcp_cli::render_json(&answer);

    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&rendered).expect("valid JSON"),
        answer,
    );
}

/// What is on disk, for a scope, as names and counts. Never an entry's environment.
#[test]
fn declared_reports_names_and_counts_and_no_values() {
    let path = scratch("declared").join("mcp.json");

    let definition = Definition {
        name: "fake".into(),
        command: Some("/bin/cat".into()),
        env: vec!["TOKEN=s3cr3t".into(), "OTHER=x".into()],
        ..Definition::default()
    };

    add(&path, &definition, false).1.expect("the entry");

    let declared = mcp_cli::declared(&path).expect("the declarations");

    assert_eq!(declared.get("fake"), Some(&2));
    assert!(
        !format!("{declared:?}").contains("s3cr3t"),
        "the declaration report cannot carry a value"
    );
}
