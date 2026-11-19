//! `aab`: a small command line front end for the AI Agent Blocklist feed.
//!
//! ```text
//! export AIAGENTBLOCKLIST_TOKEN=...            # your 32 character token
//! cargo run --example aab -- sync /var/lib/aab
//! cargo run --example aab -- check /var/lib/aab/aab_full.json api.example-agent.ai SampleAgent.exe
//! cargo run --example aab -- policy /var/lib/aab/aab_full.json chrome > ExtensionInstallBlocklist.json
//! cargo run --example aab -- stats /var/lib/aab/aab_full.json
//! ```
//!
//! Exit codes: 0 ok (or nothing matched), 1 at least one `check` hit,
//! 2 usage error, 3 feed or network error, 4 subscription ended or paused.

use aiagentblocklist::{Blocklist, Client, Error};
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  aab sync <dir> [file ...]\n  aab check <aab_full.json> <id> [id ...]\n  aab policy <aab_full.json> chrome|edge|firefox\n  aab stats <aab_full.json>"
    );
    ExitCode::from(2)
}

fn fail(e: Error) -> ExitCode {
    eprintln!("aab: {}", e);
    match e {
        Error::AccessEnded { .. } => ExitCode::from(4),
        Error::Token(_) | Error::InvalidArgument(_) => ExitCode::from(2),
        _ => ExitCode::from(3),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else { return usage() };
    let result = match cmd.as_str() {
        "sync" if args.len() >= 2 => sync(&args[1], &args[2..]),
        "check" if args.len() >= 3 => check(&args[1], &args[2..]),
        "policy" if args.len() == 3 => policy(&args[1], &args[2]),
        "stats" if args.len() == 2 => stats(&args[1]),
        _ => return usage(),
    };
    match result {
        Ok(code) => code,
        Err(e) => fail(e),
    }
}

fn sync(dir: &str, files: &[String]) -> Result<ExitCode, Error> {
    let client = Client::from_env()?;
    let names: Vec<&str> = files.iter().map(String::as_str).collect();
    for (name, changed) in client.sync(dir, &names)? {
        println!("{:<40} {}", name, if changed { "updated" } else { "unchanged" });
    }
    Ok(ExitCode::SUCCESS)
}

fn check(path: &str, ids: &[String]) -> Result<ExitCode, Error> {
    let list = Blocklist::from_file(path)?;
    let mut hits = 0;
    for id in ids {
        match list.check(id) {
            Some(e) => {
                hits += 1;
                println!("BLOCK\t{}\t{}\t{}\t{}", id, e.kind, e.agent_type, e.tool_name);
            }
            None => println!("ok\t{}", id),
        }
    }
    Ok(if hits > 0 { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

fn policy(path: &str, browser: &str) -> Result<ExitCode, Error> {
    let list = Blocklist::from_file(path)?;
    let kind = match browser {
        "chrome" => "chrome_ext",
        "edge" => "edge_ext",
        "firefox" => "firefox_ext",
        other => {
            return Err(Error::InvalidArgument(format!(
                "unknown browser {:?}, use chrome, edge or firefox",
                other
            )))
        }
    };
    let ids = list.idents_of(&[kind]);
    let doc = if kind == "firefox_ext" {
        // Firefox enterprise policy: ExtensionSettings with "blocked" per add-on ID.
        let mut settings = serde_json::Map::new();
        for id in ids {
            settings.insert(
                id.to_string(),
                serde_json::json!({ "installation_mode": "blocked" }),
            );
        }
        serde_json::json!({ "policies": { "ExtensionSettings": settings } })
    } else {
        serde_json::json!({ "ExtensionInstallBlocklist": ids })
    };
    println!("{}", serde_json::to_string_pretty(&doc).expect("valid JSON"));
    Ok(ExitCode::SUCCESS)
}

fn stats(path: &str) -> Result<ExitCode, Error> {
    let list = Blocklist::from_file(path)?;
    println!("{} version {}, {} rows", list.product(), list.version(), list.len());
    for kind in list.kinds() {
        println!("  kind {:<18} {}", kind, list.filter(None, Some(kind), None).len());
    }
    for t in list.agent_types() {
        println!("  type {:<28} {}", t, list.filter(Some(t), None, None).len());
    }
    Ok(ExitCode::SUCCESS)
}
