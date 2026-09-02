//! What a component says about itself, on the shape the rest of the system reads (contract C1).

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde_json::{Map, Value};

use crate::WORLD;

/// The most `summary` characters this crate will emit. C1 says 200; a longer one is clipped
/// here rather than refused, because a `describe` that failed to build would be a component
/// that failed to load over a docstring.
pub const MAX_SUMMARY_CHARS: usize = 200;

/// The most `examples` entries this crate will emit. C1 says four; the fifth and later are
/// dropped.
pub const MAX_EXAMPLES: usize = 4;

/// One `{"message": …, "reply": …}` pair in [`Describe::example`].
#[derive(Clone, Debug)]
pub struct Example {
    /// A body this capability accepts.
    pub message: Value,
    /// What it answers with.
    pub reply: Value,
}

/// A component's own account of itself, serialised to contract C1.
///
/// ```ignore
/// Describe::new("counter", "0.1.0")
///     .summary("Counts. Send `{\"add\": n}`, read the running total.")
///     .input_schema(json!({ "type": "object" }))
///     .example(json!({ "add": 2 }), json!({ "count": 2 }))
/// ```
///
/// # Untrusted, and stays untrusted
///
/// Everything in here is text a component authored about itself. Nothing above verifies a word
/// of it: the `world` field is filled in by this crate and the *component's own type* is what
/// `inspect` reports and what the signer records, so a `describe` claiming a world it is not in
/// changes nothing except what a reader is told.
///
/// The bounds this crate applies — [`MAX_SUMMARY_CHARS`], [`MAX_EXAMPLES`] — are a courtesy to
/// an author, not a defence: they hold only for a document this builder produced, and a guest
/// may return anything at all from `describe`. **Nothing truncates it here and nothing
/// truncates it in the helper** — a 21 KB document passes both. Contract C1's 4 KiB whole-document
/// bound and the "component-authored" label belong to whatever puts this in front of a model
/// (W13), and that consumer must apply them to a string it did not build. Write this for a
/// reader; do not write it as if it were a permission.
#[derive(Clone, Debug)]
pub struct Describe {
    name: String,
    version: String,
    /// Filled in by this crate and never by the author: [`crate::WORLD`] for the three
    /// capability-world seams, [`crate::POLICY_WORLD`] for [`crate::Policy`]. The `export_*`
    /// macro decides it, because the macro is what decides which world the component actually
    /// implements — an author who could set this could only make it disagree with the bytes.
    world: &'static str,
    summary: Option<String>,
    input_schema: Option<Value>,
    examples: Vec<Example>,
}

impl Describe {
    /// The two required fields. `name` should be in `Wasm.Artifact.name?/1`'s charset — lower
    /// alphanumerics, `-` and `_` — and `version` a semver string, because those are what the
    /// manifest that ships this component will carry.
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            world: WORLD,
            summary: None,
            input_schema: None,
            examples: Vec::new(),
        }
    }

    /// One line of plain text, clipped to [`MAX_SUMMARY_CHARS`] characters.
    pub fn summary(mut self, text: impl Into<String>) -> Self {
        let text: String = text.into();
        self.summary = Some(text.chars().take(MAX_SUMMARY_CHARS).collect());
        self
    }

    /// A JSON Schema for the message body. Absent means any JSON.
    pub fn input_schema(mut self, schema: Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// One worked example. Beyond [`MAX_EXAMPLES`] the call is a no-op: C1 bounds the list, and
    /// a builder that silently produced a document the reader would truncate is worse than one
    /// that stops where the contract does.
    pub fn example(mut self, message: Value, reply: Value) -> Self {
        if self.examples.len() < MAX_EXAMPLES {
            self.examples.push(Example { message, reply });
        }
        self
    }

    /// Restates the world this document reports. Crate-internal: the `export_*` macro that
    /// exported this component is the only thing that knows which world it is in, so it is the
    /// only thing that sets this.
    pub(crate) fn in_world(mut self, world: &'static str) -> Self {
        self.world = world;
        self
    }

    /// The C1 document. `world` is this crate's, never the author's.
    pub fn to_json(&self) -> Value {
        let mut document = Map::new();
        document.insert("name".to_string(), Value::String(self.name.clone()));
        document.insert("version".to_string(), Value::String(self.version.clone()));
        document.insert("world".to_string(), Value::String(self.world.to_string()));

        if let Some(summary) = &self.summary {
            document.insert("summary".to_string(), Value::String(summary.clone()));
        }

        if let Some(schema) = &self.input_schema {
            document.insert("input_schema".to_string(), schema.clone());
        }

        if !self.examples.is_empty() {
            let examples = self
                .examples
                .iter()
                .map(|example| {
                    let mut entry = Map::new();
                    entry.insert("message".to_string(), example.message.clone());
                    entry.insert("reply".to_string(), example.reply.clone());
                    Value::Object(entry)
                })
                .collect();
            document.insert("examples".to_string(), Value::Array(examples));
        }

        Value::Object(document)
    }

    /// The C1 document, encoded. This is what the world's `describe` export returns.
    pub fn to_json_string(&self) -> String {
        self.to_json().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Contract C1's required half, exactly. `world` is this crate's and never the author's:
    /// delete the `world` insert in `to_json` and this is the assertion that goes red.
    #[test]
    fn the_minimal_document_is_name_version_and_world() {
        assert_eq!(
            Describe::new("counter", "0.1.0").to_json(),
            json!({ "name": "counter", "version": "0.1.0", "world": WORLD })
        );
    }

    /// The optional half, under the key names C1 fixed. `input_schema` is snake_case where the
    /// hook contract's keys are camelCase, because they are two different contracts and this is
    /// the one W13 reads.
    #[test]
    fn the_optional_fields_land_under_the_names_c1_gave_them() {
        let document = Describe::new("counter", "0.1.0")
            .summary("Counts.")
            .input_schema(json!({ "type": "object" }))
            .example(json!({ "add": 1 }), json!({ "count": 1 }))
            .to_json();

        assert_eq!(document["summary"], "Counts.");
        assert_eq!(document["input_schema"], json!({ "type": "object" }));
        assert_eq!(
            document["examples"],
            json!([{ "message": { "add": 1 }, "reply": { "count": 1 } }])
        );
    }

    /// A `summary` longer than C1 admits is clipped rather than shipped whole, and clipped in
    /// *characters*: a cut that landed mid-codepoint would produce a document that is not JSON.
    #[test]
    fn a_summary_is_clipped_where_the_contract_stops() {
        let long = "é".repeat(MAX_SUMMARY_CHARS + 50);
        let document = Describe::new("n", "0.1.0").summary(long).to_json();

        let summary = document["summary"].as_str().expect("a summary");
        assert_eq!(summary.chars().count(), MAX_SUMMARY_CHARS);
        assert_eq!(summary.len(), MAX_SUMMARY_CHARS * 2, "clipped by character");
    }

    /// C1 admits at most four examples, so the fifth is not emitted. Raise the bound in
    /// `example` and this goes red.
    #[test]
    fn the_fifth_example_is_not_emitted() {
        let mut describe = Describe::new("n", "0.1.0");
        for index in 0..MAX_EXAMPLES + 3 {
            describe = describe.example(json!({ "n": index }), json!({}));
        }

        let document = describe.to_json();
        let examples = document["examples"].as_array().expect("examples");

        assert_eq!(examples.len(), MAX_EXAMPLES);
        // The first four, not the last four: an author's first examples are their best ones.
        assert_eq!(examples[0]["message"], json!({ "n": 0 }));
    }

    /// Absent rather than null: C1 says these keys are optional, and a `"summary": null` is a
    /// key that is present.
    #[test]
    fn an_unset_optional_field_is_absent_and_not_null() {
        let document = Describe::new("n", "0.1.0").to_json();

        assert!(document.get("summary").is_none());
        assert!(document.get("input_schema").is_none());
        assert!(document.get("examples").is_none());
    }
}
