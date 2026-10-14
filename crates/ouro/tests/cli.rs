//! The front door's own output contract; no fleet is contacted.
use std::process::{Command, Output};

fn ouro(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ouro"))
        .args(arguments)
        .output()
        .expect("the binary runs")
}

#[test]
fn json_prints_one_line_and_the_default_is_pretty() {
    let compact = ouro(&["version", "--json"]);
    assert!(compact.status.success());
    let text = String::from_utf8(compact.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "{text}");
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["component"], "ouro");
    let pretty = ouro(&["version"]);
    assert!(pretty.status.success());
    let text = String::from_utf8(pretty.stdout).unwrap();
    assert!(text.lines().count() > 1, "{text}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        value
    );
}

#[test]
fn kill_offers_no_signal_it_would_not_send() {
    let refused = ouro(&["fleet", "kill", "job", "--signal", "TERM"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("--signal"));
}
