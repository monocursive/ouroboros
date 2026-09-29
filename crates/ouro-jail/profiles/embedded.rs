/// Embedded profiles stay experimental until their exact version has a live A-row.
pub fn bundled_profile(name: &str) -> Option<&'static str> {
    match name {
        "aider" => Some(include_str!("launch/aider.toml")),
        "amp" => Some(include_str!("launch/amp.toml")),
        "auggie" => Some(include_str!("launch/auggie.toml")),
        "claude" => Some(include_str!("launch/claude.toml")),
        "cline" => Some(include_str!("launch/cline.toml")),
        "codex" => Some(include_str!("launch/codex.toml")),
        "copilot" => Some(include_str!("launch/copilot.toml")),
        "cursor" => Some(include_str!("launch/cursor.toml")),
        "droid" => Some(include_str!("launch/droid.toml")),
        "gemini" => Some(include_str!("launch/gemini.toml")),
        "goose" => Some(include_str!("launch/goose.toml")),
        "kilo" => Some(include_str!("launch/kilo.toml")),
        "opencode" => Some(include_str!("launch/opencode.toml")),
        "pi" => Some(include_str!("launch/pi.toml")),
        _ => None,
    }
}

pub fn bundled_fragment(name: &str) -> Option<&'static str> {
    match name {
        "containers" => Some(include_str!("bundles/containers.toml")),
        "go" => Some(include_str!("bundles/go.toml")),
        "java" => Some(include_str!("bundles/java.toml")),
        "node" => Some(include_str!("bundles/node.toml")),
        "python" => Some(include_str!("bundles/python.toml")),
        "ruby" => Some(include_str!("bundles/ruby.toml")),
        "rust" => Some(include_str!("bundles/rust.toml")),
        "scm" => Some(include_str!("bundles/scm.toml")),
        _ => None,
    }
}
