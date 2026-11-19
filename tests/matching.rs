//! Offline matching tests against tests/fixtures/aab_full.json (made-up rows).

mod common;

use aiagentblocklist::{normalize_host, pep503, Blocklist, Ecosystem, Error};
use common::FIXTURE;

fn list() -> Blocklist {
    Blocklist::from_json(FIXTURE).expect("fixture parses")
}

#[test]
fn header_fields_and_counts() {
    let l = list();
    assert_eq!(l.product(), "AI Agent Blocklist");
    assert_eq!(l.version(), "test-1");
    assert_eq!(l.len(), 16);
    assert_eq!(l.count("domains"), Some(3));
    assert_eq!(l.count("npm_packages"), Some(2));
    assert_eq!(l.columns().len(), 10);
    assert_eq!(l.entries()[0].ident, "example-agent.ai");
}

#[test]
fn from_file_and_reader_match_from_json() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/aab_full.json");
    let a = Blocklist::from_file(path).unwrap();
    let b = Blocklist::from_reader(FIXTURE.as_bytes()).unwrap();
    assert_eq!(a.entries(), b.entries());
    assert_eq!(a.version(), b.version());
}

#[test]
fn bad_json_is_an_error() {
    let err = Blocklist::from_json("{not json").unwrap_err();
    assert_eq!(err.status(), 0);
    assert!(matches!(err, Error::Other { .. }));
}

#[test]
fn counts_ignore_non_numbers() {
    let l = Blocklist::from_json(r#"{"counts":{"domains":2,"note":"x"},"entries":[]}"#).unwrap();
    assert_eq!(l.count("domains"), Some(2));
    assert_eq!(l.count("note"), None);
    assert!(l.is_empty());
}

#[test]
fn domain_exact_and_parent() {
    let l = list();
    assert_eq!(l.check_domain("example-agent.ai").unwrap().tool_name, "Example Agent");
    assert_eq!(l.check_domain("api.example-agent.ai").unwrap().ident, "example-agent.ai");
    assert_eq!(l.check_domain("a.b.c.sample-browser.app").unwrap().agent_type, "AI browser");
}

#[test]
fn domain_label_boundaries() {
    let l = list();
    assert!(l.check_domain("notexample-agent.ai").is_none());
    assert!(l.check_domain("example-agent.ai.other.test").is_none());
    assert!(l.check_domain("xample-agent.ai").is_none());
    assert!(l.check_domain("ai").is_none());
    assert!(l.check_domain("").is_none());
}

#[test]
fn url_normalisation() {
    let l = list();
    for input in [
        "HTTPS://user:secret@API.Example-Agent.AI:8443/v1/run?x=1#frag",
        "http://example-agent.ai",
        "example-agent.ai:443",
        "Example-Agent.AI.",
        "//cdn.example-agent.ai/script.js",
        "  wss://stream.example-agent.ai/socket  ",
        "example-agent.ai/path?q=http://elsewhere.test",
    ] {
        assert!(l.check_domain(input).is_some(), "{} should match", input);
    }
    assert_eq!(
        normalize_host("HTTPS://user:pw@API.Example-Agent.AI:8443/a?b#c").as_deref(),
        Some("api.example-agent.ai")
    );
    assert_eq!(normalize_host("[::1]:8080").as_deref(), Some("::1"));
    assert_eq!(normalize_host("sample-browser.app..").as_deref(), Some("sample-browser.app"));
    assert_eq!(normalize_host("https:///nothing"), None);
}

#[test]
fn domain_check_ignores_other_kinds() {
    let l = list();
    // A bundle ID and a jetbrains plugin ID look like reversed domains.
    assert!(l.check_domain("com.example.agentbrowser").is_none());
    assert!(l.check_domain("com.example.agent.jetbrains").is_none());
    assert!(l.check_domain("demo-mcp-server").is_none());
}

#[test]
fn extensions_case_insensitive() {
    let l = list();
    let chrome = l.check_extension("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP").unwrap();
    assert_eq!(chrome.kind, "chrome_ext");
    assert_eq!(l.check_extension("ponmlkjihgfedcbaponmlkjihgfedcba").unwrap().kind, "edge_ext");
    assert_eq!(l.check_extension("Agent@Example-Agent.AI").unwrap().kind, "firefox_ext");
    assert_eq!(l.check_extension(" exampleagent.agent-helper ").unwrap().kind, "vscode_ext");
    assert_eq!(l.check_extension("com.example.agent.jetbrains").unwrap().kind, "jetbrains_plugin");
    assert!(l.check_extension("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none());
    // Not an extension kind.
    assert!(l.check_extension("com.example.agentbrowser").is_none());
}

#[test]
fn processes_with_and_without_exe() {
    let l = list();
    assert_eq!(l.check_process("SampleAgent.exe").unwrap().kind, "process_win");
    assert_eq!(l.check_process("sampleagent").unwrap().kind, "process_win");
    assert_eq!(l.check_process("SAMPLEAGENT.EXE").unwrap().kind, "process_win");
    assert_eq!(l.check_process("DEMO-AGENT.EXE").unwrap().kind, "process_cli");
    assert_eq!(l.check_process("demo-agent").unwrap().kind, "process_cli");
    assert_eq!(l.check_process("sample browser").unwrap().kind, "process_mac");
    assert_eq!(
        l.check_process(r"C:\Program Files\Example\SampleAgent.exe").unwrap().kind,
        "process_win"
    );
    assert_eq!(l.check_process("/usr/local/bin/demo-agent").unwrap().kind, "process_cli");
    assert!(l.check_process("agent").is_none());
    assert!(l.check_process(".exe").is_none());
    assert!(l.check_process("").is_none());
}

#[test]
fn npm_packages_lowercase() {
    let l = list();
    assert_eq!(l.check_package(Ecosystem::Npm, "Demo-MCP-Server").unwrap().kind, "npm");
    assert_eq!(l.check_package(Ecosystem::Npm, "@Example/Agent-CLI").unwrap().risk_grade, "Low");
    // npm does not normalise separators.
    assert!(l.check_package(Ecosystem::Npm, "demo_mcp_server").is_none());
}

#[test]
fn pypi_pep503() {
    let l = list();
    for name in ["demo-mcp-server", "Demo_MCP.Server", "DEMO__mcp..server", "demo.mcp_server"] {
        assert_eq!(l.check_package(Ecosystem::Pypi, name).unwrap().kind, "pypi", "{}", name);
    }
    assert!(l.check_package(Ecosystem::Pypi, "demo-mcp").is_none());
    assert_eq!(pep503("A-_.b__C"), "a-b-c");
}

#[test]
fn ecosystem_parsing() {
    assert_eq!("NPM".parse::<Ecosystem>().unwrap(), Ecosystem::Npm);
    assert_eq!(" pypi ".parse::<Ecosystem>().unwrap(), Ecosystem::Pypi);
    assert!(matches!("cargo".parse::<Ecosystem>(), Err(Error::InvalidArgument(_))));
}

#[test]
fn check_tries_domains_then_idents() {
    let l = list();
    assert_eq!(l.check("https://x.sample-browser.app/").unwrap().kind, "domain");
    assert_eq!(l.check("com.example.agentbrowser").unwrap().kind, "mac_bundle_id");
    assert_eq!(l.check("ExampleCorp.AgentDesktop").unwrap().kind, "winget");
    assert_eq!(l.check("examplecorp.agentdesktop").unwrap().kind, "winget");
    assert_eq!(l.check("Sample Browser").unwrap().kind, "process_mac");
    // The firefox ID carries a listed domain after the '@', so domains win.
    assert_eq!(l.check("agent@example-agent.ai").unwrap().kind, "domain");
    assert!(l.check("unlisted-thing").is_none());
}

#[test]
fn filter_by_fields() {
    let l = list();
    assert_eq!(l.filter(None, Some("domain"), None).len(), 3);
    assert_eq!(l.filter(Some("mcp server"), None, None).len(), 3);
    assert_eq!(l.filter(None, None, Some("High")).len(), 3);
    assert_eq!(l.filter(Some("Coding agent"), Some("npm"), None).len(), 1);
    assert_eq!(l.filter(None, None, None).len(), 16);
    assert_eq!(l.filter(Some(""), Some(""), Some("")).len(), 16);
    assert!(l.filter(Some("Voice agent"), None, None).is_empty());
    let graded: Vec<_> = l.filter(None, Some("domain"), Some("elevated"));
    assert_eq!(graded[0].ident, "sample-browser.app");
}

#[test]
fn lists_of_domains_types_and_kinds() {
    let l = list();
    assert_eq!(l.domains(), ["example-agent.ai", "sample-browser.app", "demo-mcp-server.dev"]);
    assert_eq!(
        l.agent_types(),
        [
            "AI browser",
            "Autonomous agent",
            "Browser agent",
            "Coding agent",
            "MCP server",
            "Personal AI assistant"
        ]
    );
    assert_eq!(l.kinds().len(), 13);
    assert!(l.kinds().windows(2).all(|w| w[0] < w[1]));
    assert_eq!(l.idents_of(&["chrome_ext"]), ["abcdefghijklmnopabcdefghijklmnop"]);
}

#[test]
fn blocklist_is_send_and_sync() {
    fn assert_both<T: Send + Sync>() {}
    assert_both::<Blocklist>();
    assert_both::<aiagentblocklist::Client>();
}
