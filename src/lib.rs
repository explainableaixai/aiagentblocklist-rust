//! Feed client for the [AI Agent Blocklist](https://www.aiagentblocklist.com).
//!
//! The list covers AI agents, AI browsers, coding agents and MCP servers:
//! 2,600+ AI agent domains and 5,300+ device identifiers (browser extension
//! IDs, macOS bundle IDs, Windows package IDs, process names, npm and PyPI
//! packages, Homebrew casks and formulae, editor plugin IDs). It is rebuilt
//! every day behind a private download link.
//!
//! There is no per-request API. This crate downloads the files with
//! conditional requests, keeps them on disk and matches locally:
//!
//! ```no_run
//! use aiagentblocklist::{Client, Ecosystem};
//!
//! let client = Client::from_env()?; // AIAGENTBLOCKLIST_TOKEN
//! client.sync("/var/lib/aiagentblocklist", &["aab_full.json", "domains.txt"])?;
//!
//! let list = aiagentblocklist::Blocklist::from_file("/var/lib/aiagentblocklist/aab_full.json")?;
//! if let Some(hit) = list.check_domain("https://api.example-agent.ai/v1/run") {
//!     println!("{} ({})", hit.tool_name, hit.agent_type);
//! }
//! let _ = list.check_package(Ecosystem::Pypi, "Demo_MCP.Server");
//! # Ok::<(), aiagentblocklist::Error>(())
//! ```

#![deny(missing_docs)]

mod blocklist;
mod client;
mod error;

pub use blocklist::{normalize_host, pep503, Blocklist, Ecosystem, Entry};
pub use client::{
    bare_etag, validate_file_name, validate_token, Client, ClientBuilder, DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, FILES, TOKEN_ENV, VERSION,
};
pub use error::{Error, Result};
