# aiagentblocklist for Rust

A Rust crate, plus two small command line tools, for the [AI Agent Blocklist data feed](https://www.aiagentblocklist.com/ai-agent-blocklist.php). It pulls the daily files over HTTPS, remembers what it already has, and answers one question from memory: is this host, extension, process or package on the list?

The feed covers 2,600+ AI agent domains and 5,300+ device identifiers. Nothing here calls a remote lookup service. You download, you cache, and you match on your own machine.

```text
$ export AIAGENTBLOCKLIST_TOKEN=...        # 32 letters and digits from your download link
$ aab sync /var/lib/aab
aab_full.csv                             updated
aab_full.json                            updated
domains.txt                              updated
...
$ aab check /var/lib/aab/aab_full.json https://api.example-agent.ai/v1 SampleAgent.exe unlisted.test
BLOCK   https://api.example-agent.ai/v1   domain        Autonomous agent   Example Agent
BLOCK   SampleAgent.exe                   process_win   Autonomous agent   Example Agent
ok      unlisted.test
```

The `aab` binary above is `examples/aab.rs` from this repository, built with `cargo build --release --example aab`.

## Why agents need their own list

An AI agent is not a passive website. Once someone signs in, it clicks, types, reads mail, opens repositories and calls tools, and it does all of that with the permissions of the person who started it. A browser with a built in agent, an assistant in a terminal or an MCP server wired into an editor can reach the same files, tokens and internal pages as its user.

Most of these tools were never reviewed by anyone in security. They show up through a browser extension, an `npm install`, a Homebrew cask or a download from a vendor page, and they keep running with whatever access the laptop has. Our overview of [risks that coding agents bring to a codebase](https://www.aiagentblocklist.com/coding-agents/coding-agent-security-risks.php) walks through the developer side of that picture.

The feed answers with plain data. Each row names one concrete thing to block: a domain, an extension ID, a bundle ID, a process name or a package. This crate is the Rust way to fetch those rows and put them to work inside your own tooling.

## Installation

Add the crate with Cargo:

```text
cargo add aiagentblocklist
```

or by hand in `Cargo.toml`:

```toml
[dependencies]
aiagentblocklist = "1.0"
```

The client is blocking and synchronous. It depends on `ureq` (with rustls), `serde` and `serde_json`, and nothing else, so there is no async runtime to pull in.

Downloads need a subscription. Plans and terms are listed on [our pricing page](https://www.aiagentblocklist.com/pricing.php); after sign up you get a private link that carries a 32 character token. Put the token in `AIAGENTBLOCKLIST_TOKEN` or pass it in code.

## Quick start

```rust
use aiagentblocklist::{Blocklist, Client, Ecosystem};

fn main() -> Result<(), aiagentblocklist::Error> {
    let client = Client::from_env()?;
    let changed = client.download_to("aab_full.json", "/var/lib/aab/aab_full.json")?;
    println!("feed changed: {changed}");

    let list = Blocklist::from_file("/var/lib/aab/aab_full.json")?;
    println!("{} rows, version {}", list.len(), list.version());

    if let Some(hit) = list.check_domain("wss://relay.example-agent.ai:443/session") {
        println!("{} is listed as {} ({})", hit.ident, hit.agent_type, hit.risk_grade);
    }
    if list.check_package(Ecosystem::Pypi, "Demo_MCP.Server").is_some() {
        println!("that PyPI package is on the list");
    }
    Ok(())
}
```

Two things happen in that program. `download_to` sends a conditional request and rewrites the file only when the content moved on. `Blocklist::from_file` parses the JSON and builds every lookup table once, so each later check is a hash lookup with no I/O at all.

## The files behind your token

Every file lives under `/download/<TOKEN>/` on www.aiagentblocklist.com, one level below the folder page. The link stays the same while the content is rebuilt every day, and the constant `FILES` holds all nineteen names in the order `sync_all` fetches them.

For a command-line tool or a log matcher, a handful of them matter:

| File | Typical use from Rust |
|---|---|
| `aab_full.json` | the full data set this crate parses |
| `process_names.txt` | grep-style matching against process accounting or EDR exports |
| `pypi_packages.txt`, `npm_packages.txt` | deny lists for a package mirror or a CI step |
| `domains.txt` | one domain per line, for tools that cannot read JSON |
| `aab_full.csv` | the same rows, for a SIEM lookup table |
| `counts.json` | a quick sanity check after each sync |

Everything else in the folder targets other teams. Network staff get a response policy zone, a PAC file, a hosts file and a firewall list; desktop admins get Chrome and Edge extension policies in three formats. Windows package IDs, Mac bundle IDs and Firefox add-on IDs each have their own text file, and a short README explains the lot.

Each `Entry` has ten `String` fields. The ones you will reach for most are `ident` (the value to block), `kind`, `agent_type` and `risk_grade`; the rest (`tool_name`, `tool_domain`, `name`, `platform`, `category` and `subcategory`) describe the tool the row belongs to.

The `kind` column tells you what `ident` holds, for example `domain`, `chrome_ext`, `process_win`, `brew_cask` or `jetbrains_plugin`. The grade is Low, Moderate, Elevated, High, Severe or Not graded.

## API at a glance

| Item | What it does |
|---|---|
| `Client::new(token)`, `Client::from_env()` | validate the token; no request yet |
| `Client::builder()` | set `base_url`, `timeout`, `user_agent`, `proxy_from_env` or your own `ureq::Agent` |
| `client.file_url(name)` | full URL for one file (it contains the token) |
| `client.download(name)` | body as `Vec<u8>`; `download_string` returns text |
| `client.download_to(name, path)` | fetch only if the server copy moved on; returns `true` after a rewrite |
| `client.sync(dir, &names)` | `download_to` per name; an empty slice means every file |
| `client.load_blocklist()` | fetch and parse `aab_full.json` in one call |
| `Blocklist::from_file`, `from_json`, `from_slice`, `from_reader` | offline parsing |
| `list.check_domain(host_or_url)` | the host or any parent domain, rows of kind `domain` only |
| `list.check_extension(id)` | Chrome, Edge, Firefox, VS Code, Open VSX and JetBrains IDs |
| `list.check_process(name)` | process and command names; paths and `.exe` handled |
| `list.check_package(Ecosystem::Npm or Ecosystem::Pypi, name)` | package names with each registry's rules |
| `list.check(identifier)` | domain rules first, then any identifier |
| `list.filter(agent_type, kind, risk_grade)` | one `Option<&str>` per field, case-insensitive |
| `list.domains()`, `agent_types()`, `kinds()`, `idents_of(&[kind])` | distinct values |
| `normalize_host`, `pep503`, `bare_etag` | the helpers the checks rely on |

Every `check_*` method returns `Option<&Entry>`, borrowed from the list. Clone the `Entry` if it has to outlive the `Blocklist` it came from.

## How the matching behaves

**Domains.** Input can be a bare host or a whole URL. We strip the scheme, user info, port, path, query and fragment, lowercase the rest and drop a trailing dot, then try the host followed by each parent. `wss://u@API.Example-Agent.AI:8443/x?y#z` therefore hits a row for `example-agent.ai`, while `notexample-agent.ai` does not, because the walk only ever cuts at a dot.

**Extensions.** Exact comparison that ignores case, across all six extension and plugin kinds. A Chrome ID pasted in capitals from a ticket still matches.

**Processes.** A full path is reduced to its last component, so a Windows path from an endpoint event works as is. The `.exe` suffix is optional in both directions: `SampleAgent.exe` in the list matches `sampleagent`, and a listed `demo-agent` matches `DEMO-AGENT.EXE`.

**Packages.** npm names compare in lower case. PyPI names go through [PEP 503 normalisation](https://peps.python.org/pep-0503/), which folds `Demo_MCP.Server`, `demo.mcp_server` and `DEMO__mcp..server` into a single key.

**Anything.** `check` is the catch-all for mixed input such as a column of indicators from an incident note. It tries domain rules first and exact identifiers after that.

## Conditional downloads and the sidecar file

`download_to` writes the server's ETag into `<path>.etag`. On the next call it sends that value as `If-None-Match`, and a 304 answer leaves your copy alone and returns `false`. Fresh content goes to a temporary file in the same directory and is renamed over the old one, so a resolver or proxy reading the file never sees half a list.

Compressed responses can carry a weak tag or a `-gzip` suffix. The crate compares the bare value, so a 200 that repeats the same tag still counts as unchanged and the file is not rewritten.

The sidecar is only trusted while the data file next to it exists. When an answer has no ETag, the sidecar is overwritten with an empty string rather than removed.

## Worked example: a cron friendly CLI

`examples/aab.rs` is about a hundred lines and covers the routine chores: sync a directory, check values, print browser policies and show totals. Build it once and install the binary wherever your scheduler can reach it.

```text
cargo build --release --example aab
install -m 0755 target/release/examples/aab /usr/local/bin/aab
```

```text
# /etc/cron.d/aab: unchanged files cost one small 304 each
17 */4 * * * aab  /usr/local/bin/aab sync /var/lib/aab >> /var/log/aab-sync.log 2>&1
```

Cron files accept `NAME=value` lines, so the token can sit in a root only file like this one; a systemd timer with an `EnvironmentFile` works just as well. Avoid passing it as a command argument, where process listings would show it.

Exit codes are meant for shell scripts:

| Code | Meaning |
|---|---|
| 0 | success, or `check` found nothing |
| 1 | `check` found at least one listed value |
| 2 | usage error or a malformed token |
| 3 | network, file or feed problem |
| 4 | the subscription has ended or is paused |

```text
$ aab policy /var/lib/aab/aab_full.json chrome > /etc/opt/chrome/policies/managed/aab.json
$ aab policy /var/lib/aab/aab_full.json firefox > /etc/firefox/policies/policies.json
```

The `policy` subcommand prints an `ExtensionInstallBlocklist` document for Chrome or Edge, or an `ExtensionSettings` document with blocked add-ons for Firefox. The feed already ships ready made policy files, so this is mainly useful when you want to merge our IDs with an in-house list before rollout.

## Worked example: a fast matcher for log files

`examples/scan_log.rs` reads a proxy, DNS or web server log line by line. It splits each line on whitespace, quotes and a few separators, checks every token that contains a dot, and prints the line number, the listed domain, the agent type and the original token. A per tool summary goes to stderr at the end.

```text
cargo build --release --example scan_log
target/release/examples/scan_log /var/lib/aab/aab_full.json /var/log/proxy/access.log
zcat /var/log/dns/queries-*.gz | target/release/examples/scan_log /var/lib/aab/aab_full.json -
```

The speed comes from doing the expensive work once. The list is parsed at start up; each domain check makes one lowercase copy and then walks parent labels as borrowed slices against a `HashMap`. In our own run over a synthetic proxy log of two million lines, a single core finished in about two seconds.

Lines are read as bytes and viewed lossily, so a stray invalid byte does not stop the scan. For structured output, replace the `writeln!` with `serde_json::to_writer`, since `Entry` derives `Serialize`.

The heart of it fits in a few lines if you want to embed it elsewhere:

```rust
use std::io::BufRead;
use aiagentblocklist::Blocklist;

let list = Blocklist::from_file("/var/lib/aab/aab_full.json")?;
for line in std::io::stdin().lock().lines() {
    let line = line?;
    if let Some(hit) = line.split_whitespace().find_map(|t| list.check_domain(t)) {
        println!("{}\t{}\t{}", hit.ident, hit.agent_type, line);
    }
}
```

## Worked example: tower middleware for outbound calls

Services that host agents or run tool calls for users often make HTTP requests to whatever URL a model produced. A small tower layer can refuse listed hosts before the request leaves your network. The crate has no tower dependency; the sketch below lives in your own service and assumes `tower`, `http` and `futures`.

```rust
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use aiagentblocklist::Blocklist;
use futures::future::BoxFuture;
use tower::{Layer, Service};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone)]
pub struct AgentEgressLayer {
    pub list: Arc<RwLock<Blocklist>>,
}

impl<S> Layer<S> for AgentEgressLayer {
    type Service = AgentEgress<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AgentEgress { inner, list: self.list.clone() }
    }
}

#[derive(Clone)]
pub struct AgentEgress<S> {
    inner: S,
    list: Arc<RwLock<Blocklist>>,
}

impl<S, B> Service<http::Request<B>> for AgentEgress<S>
where
    S: Service<http::Request<B>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<S::Response, BoxError>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let host = req.uri().host().unwrap_or_default().to_owned();
        let listed = self.list.read().unwrap().check_domain(&host).map(|e| e.tool_name.clone());
        if let Some(tool) = listed {
            return Box::pin(async move { Err(format!("{host} is on the agent list ({tool})").into()) });
        }
        let fut = self.inner.call(req);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}
```

Refreshing the shared list is a plain thread. It calls `download_to` every few hours and takes the write lock only when the file really changed:

```rust
use std::{sync::{Arc, RwLock}, thread, time::Duration};
use aiagentblocklist::{Blocklist, Client};

const PATH: &str = "/var/lib/aab/aab_full.json";

let shared = Arc::new(RwLock::new(Blocklist::from_file(PATH)?));
let writer = Arc::clone(&shared);
thread::spawn(move || {
    let client = Client::from_env().expect("AIAGENTBLOCKLIST_TOKEN");
    loop {
        match client.download_to("aab_full.json", PATH) {
            Ok(true) => match Blocklist::from_file(PATH) {
                Ok(fresh) => *writer.write().unwrap() = fresh,
                Err(e) => eprintln!("keeping the previous list: {e}"),
            },
            Ok(false) => {}
            Err(e) => eprintln!("refresh failed, will retry: {e}"),
        }
        thread::sleep(Duration::from_secs(4 * 3600));
    }
});
```

The same layer can guard the server side of an axum or hyper app too. One handy spot is the handler where users register webhook or callback URLs: reject a listed host before you store it.

## Worked example: gate dependencies in CI

Coding agents and MCP servers often arrive as ordinary packages. A short CI step can fail a pull request that adds one to `package.json` or `requirements.txt`:

```rust
use aiagentblocklist::{Blocklist, Ecosystem};

let list = Blocklist::from_file("aab_full.json")?;
let mut found = Vec::new();

let manifest: serde_json::Value = serde_json::from_str(&std::fs::read_to_string("package.json")?)?;
for section in ["dependencies", "devDependencies"] {
    if let Some(deps) = manifest[section].as_object() {
        for name in deps.keys() {
            if let Some(e) = list.check_package(Ecosystem::Npm, name) {
                found.push(format!("npm {name}: {} ({})", e.agent_type, e.tool_name));
            }
        }
    }
}

for line in std::fs::read_to_string("requirements.txt")?.lines() {
    let name = line.split(['=', '<', '>', '~', '!', '[', ';', ' ']).next().unwrap_or("").trim();
    if name.is_empty() || name.starts_with('#') || name.starts_with('-') {
        continue;
    }
    if let Some(e) = list.check_package(Ecosystem::Pypi, name) {
        found.push(format!("pypi {name}: {}", e.agent_type));
    }
}

if !found.is_empty() {
    eprintln!("listed AI agent packages:\n{}", found.join("\n"));
    std::process::exit(1);
}
```

A package gate works well next to rules about credentials. Our page on [keeping agents away from secrets and API keys](https://www.aiagentblocklist.com/coding-agents/stop-ai-agents-reading-secrets.php) covers the controls that usually sit beside it.

## Error handling

Every fallible call returns `aiagentblocklist::Result<T>`. The `Error` enum is marked `#[non_exhaustive]`, so keep a catch-all arm.

| Variant | When it happens | `status()` |
|---|---|---|
| `Error::Token` | token missing or not 32 letters and digits; raised before any request | 0 |
| `Error::InvalidArgument` | a bad file name or an unknown package ecosystem | 0 |
| `Error::NotFound { file }` | HTTP 404: the token or the file name is unknown | 404 |
| `Error::AccessEnded { file }` | HTTP 403: the subscription has ended or is paused | 403 |
| `Error::Http { status, file }` | any other answer outside 2xx | that status |
| `Error::Other { message, source }` | network, file system or JSON trouble | 0 |

```rust
use aiagentblocklist::{Client, Error};

let client = Client::from_env()?;
match client.sync("/var/lib/aab", &[]) {
    Ok(report) => {
        let changed = report.iter().filter(|(_, c)| *c).count();
        println!("{changed} files changed");
    }
    Err(Error::AccessEnded { .. }) => {
        // stop retrying and raise an alert: the subscription needs attention
    }
    Err(Error::NotFound { file }) => eprintln!("token or file name not known: {file}"),
    Err(e) if e.status() >= 500 => eprintln!("server side trouble, try later: {e}"),
    Err(e) => return Err(e.into()),
}
```

Messages never include the token. Transport failures from `ureq` normally print the full URL, so we rebuild those messages from the error kind and cause instead. `Error` implements `std::error::Error` and keeps the cause in `source()`, which makes it play well with `anyhow`, `eyre` or a plain `Box<dyn Error>`.

A failed refresh never touches the copy already on disk. Keep enforcing from the old file and retry on the next run.

## Threads, proxies and timeouts

`Client` and `Blocklist` are both `Send + Sync`, and `Client` is cheap to clone. The default timeout is 30 seconds per request; change it with `Client::builder().timeout(..)`.

Outbound proxies from `HTTPS_PROXY`, `HTTP_PROXY` or `ALL_PROXY` are picked up by default. Switch that off with `.proxy_from_env(false)`, or pass a fully configured `ureq::Agent` through `.agent(..)` when you need private roots or a fixed proxy.

The default User-Agent is `aiagentblocklist-rust/1.0.0` followed by the product site in parentheses. Replace it with `.user_agent(..)` if your egress rules key on that header.

## Where a Rust client fits

A Rust binary is rarely the only enforcement point. The same daily files feed DNS, firewall and endpoint tools, while your code covers the places those tools cannot see: application logs, CI pipelines and the outbound calls of an agent platform. Before blocking anything, many teams first take stock, and our guide to [building an AI agent inventory](https://www.aiagentblocklist.com/ai-agents/ai-agent-inventory.php) shows one way to start.

Agents that drive a desktop or a browser on their own deserve extra care, because they act inside the user's session. The page on [agents that operate a computer](https://www.aiagentblocklist.com/ai-agents/computer-use-agents-security.php) lists the controls we see most often, and the [MCP checklist for security teams](https://www.aiagentblocklist.com/mcp/mcp-security-checklist.php) pairs well with `check_package` and `check_extension`.

For shared vocabulary in threat models, the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) and [MITRE ATLAS](https://atlas.mitre.org/) are useful references. [CISA's AI pages](https://www.cisa.gov/ai) collect guidance for operators, and `hosts.txt` follows the classic [hosts file](https://en.wikipedia.org/wiki/Hosts_%28file%29) layout.

## FAQ

### Does the crate send my URLs or logs anywhere?

No. The only requests it makes go to the download URLs for your token. Matching happens inside your process, against the file on disk.

### How often should the sync run?

The files are rebuilt every day. Running the sync every few hours is fine, since an unchanged file costs a single small request that comes back as 304.

### Can I call it from async code?

Yes. Downloads block, so run them in `tokio::task::spawn_blocking` or on a plain thread. The checks never block and can be called straight from an async handler.

### What happens when the subscription ends?

Downloads return `Error::AccessEnded`, which is HTTP 403. Files already on disk stay put, so enforcement keeps working from the last copy until access returns.

### Why does `check` return a domain row for a Firefox add-on ID?

Many Firefox IDs look like `name@domain`. `check` tries the domain rules first and strips the part before the `@`, so a listed domain wins; call `check_extension` when you know the input is an add-on.

### Does it work on Windows and macOS?

Yes. The crate uses portable `std` APIs and rustls, and the atomic replace relies on `std::fs::rename`, which overwrites the target on Linux, macOS and Windows alike.

### Which Rust toolchain do I need?

A current stable toolchain with edition 2021. There is no build script and no nightly feature.

## Links

- Source code: [aiagentblocklist-rust on GitHub](https://github.com/explainableaixai/aiagentblocklist-rust)
- Crate page: [aiagentblocklist on crates.io](https://crates.io/crates/aiagentblocklist)
- API docs: [docs.rs/aiagentblocklist](https://docs.rs/aiagentblocklist)
- Questions about the data or your subscription: [write to us](https://www.aiagentblocklist.com/contact.php) or email info@alpha-quantum.com
- Release notes: [CHANGELOG.md](CHANGELOG.md)

Product names are trademarks of their respective owners.

## License

The client code is released under the MIT license; see [LICENSE](LICENSE). The feed itself is covered by your subscription terms.

## Related

- [AI tools blocklist](https://www.aitoolsblocklist.com), for AI apps and chat sites in general.
- [App blocklist for MDM](https://www.appblocklist.com), for phone and desktop apps.
- [Web filtering database](https://www.webfilteringdatabase.com), for sorting the rest of the web into categories.
