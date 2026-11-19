//! `scan_log`: find AI agent traffic in a proxy, DNS or web server log.
//!
//! ```text
//! cargo run --release --example scan_log -- /var/lib/aab/aab_full.json /var/log/squid/access.log
//! zcat dns-*.log.gz | cargo run --release --example scan_log -- /var/lib/aab/aab_full.json -
//! ```
//!
//! Each line is split into tokens on whitespace, quotes and a few
//! separators. Tokens that contain a dot are matched as hosts or URLs
//! (parent domains included). The output is one tab separated line per
//! hit, and a summary per tool on stderr at the end.

use aiagentblocklist::Blocklist;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: scan_log <aab_full.json> <logfile|->");
        std::process::exit(2);
    }
    let list = Blocklist::from_file(&args[0])?;
    let input: Box<dyn BufRead> = if args[1] == "-" {
        Box::new(BufReader::new(io::stdin().lock()))
    } else {
        Box::new(BufReader::with_capacity(1 << 20, File::open(&args[1])?))
    };

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut per_tool: HashMap<String, u64> = HashMap::new();
    let (mut lines, mut hits) = (0u64, 0u64);
    let mut buf = Vec::with_capacity(4096);
    let mut input = input;

    loop {
        buf.clear();
        if input.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        lines += 1;
        // Logs are not always valid UTF-8; a lossy view is fine for matching.
        let line = String::from_utf8_lossy(&buf);
        let tokens = line.split(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '|' | '<' | '>' | '(' | ')')
        });
        for token in tokens.filter(|t| t.contains('.')) {
            if let Some(e) = list.check_domain(token) {
                hits += 1;
                *per_tool.entry(e.tool_name.clone()).or_default() += 1;
                writeln!(out, "{}\t{}\t{}\t{}", lines, e.ident, e.agent_type, token)?;
                break; // one hit per line is enough
            }
        }
    }
    out.flush()?;

    let mut summary: Vec<_> = per_tool.into_iter().collect();
    summary.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    eprintln!("{} lines, {} lines with a listed host", lines, hits);
    for (tool, n) in summary.iter().take(25) {
        eprintln!("{:>8}  {}", n, tool);
    }
    Ok(())
}
