//! The `ouro` client, as a library so the binary and the tests speak to it the same way.
//!
//! The library half of the `ouro` product: runtime discovery and supervision, the bounded
//! gateway transport and tolerant wire model, the Ratatui application, headless and ACP
//! modes, fleet lifecycle, signed updates, MCP bridging, and the CLI surfaces that compose
//! them. Keeping these modules in the library lets integration tests drive the same code
//! the binary dispatches.

pub mod acp_serve;
pub mod agents;
pub mod cli;
pub mod clipboard;
pub mod config;
pub mod continuation;
pub mod desktop_cli;
pub mod fleet;
pub mod fleet_add;
pub mod hook;
pub mod images;
pub mod keymap;
pub mod ledger_cli;
pub mod mcp_cli;
pub mod mcp_serve;
pub mod model;
pub mod proto;
pub mod replay_cli;
pub mod run;
pub mod runtime;
pub mod status;
pub mod transport;
pub mod ui;
pub mod update;
pub mod wasm_cli;
pub mod wasm_client;
pub mod web_cli;
