# Pre-J3 action and message baseline

`action_message_baseline.exs` was captured with the original compiled action and
signal modules before the dependencies were removed. The fixture records the
source revision, SHA-256 hashes of the relevant local source files, and full lock
entries: Jido 2.3.3, Jido Action 2.3.2, Jido Signal 2.2.2, and NimbleOptions 1.1.1.

The 16 direct action cases cover required/default values, explicit values,
positive bounds, nulls, primitives, lists, nested data, unknown keys, and atom versus
string precedence. Four malformed argument cases pass through the real native tool
execution boundary. The 13 message cases retain the complete struct field map and
JSON object, including ID/time/source/subject/content metadata, extension data,
causation defaults, and visible failures. Fixed IDs and times make the corpus
repeatable without rewriting production identifiers.

The capture started only the signal dependency's extension registry and used the
existing synthetic action under standard audit mode. No provider, workspace,
network, mesh or WASM effect ran. The first attempts, which lacked the registry or
exception capture for malformed signal data, wrote no fixture.

Reproduce in a separate pre-J3 checkout, copying the capture helper there:

```sh
MIX_ENV=test mix run --no-start --no-compile scripts/capture_action_message_baseline.exs
```

The capture script refuses owned action modules. The parity test compares the
frozen observations without replacing their expected results. The pre-J1 schema
and behavior fixtures remain unchanged and are independent gates.

The owned action replaces the internal exception class with
`Ouroboros.Action.ValidationError`; its message and normalized tool result remain
identical. The message's executable struct module becomes
`Ouroboros.Signals.AgentMessage`; its serialized JSON and inspected field values
remain identical. Legacy `jido_dispatch` is retained as opaque metadata only.
Direct non-map action validation now returns an owned validation error; native
execution still performs its existing map normalization before that boundary.
