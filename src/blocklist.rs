//! Offline parsing and matching of `aab_full.json`.

use crate::error::{Error, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

/// One row of the feed. Every field is a string; missing fields are empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Entry {
    /// Name of the AI agent or tool the row belongs to.
    #[serde(default, deserialize_with = "lenient_string")]
    pub tool_name: String,
    /// Main domain of that tool.
    #[serde(default, deserialize_with = "lenient_string")]
    pub tool_domain: String,
    /// Top level category.
    #[serde(default, deserialize_with = "lenient_string")]
    pub category: String,
    /// Finer category, sometimes several joined with `; `.
    #[serde(default, deserialize_with = "lenient_string")]
    pub subcategory: String,
    /// One of the agent types, for example `Coding agent` or `MCP server`.
    #[serde(default, deserialize_with = "lenient_string")]
    pub agent_type: String,
    /// What `ident` is: `domain`, `chrome_ext`, `process_win`, `npm` and so on.
    #[serde(default, deserialize_with = "lenient_string")]
    pub kind: String,
    /// The value to block: a domain, an extension ID, a process name, a package name.
    #[serde(default, deserialize_with = "lenient_string")]
    pub ident: String,
    /// Display name of this identifier.
    #[serde(default, deserialize_with = "lenient_string")]
    pub name: String,
    /// Where the identifier applies, for example `Chrome`, `macOS` or `npm`.
    #[serde(default, deserialize_with = "lenient_string")]
    pub platform: String,
    /// `Low`, `Moderate`, `Elevated`, `High`, `Severe` or `Not graded`.
    #[serde(default, deserialize_with = "lenient_string")]
    pub risk_grade: String,
}

impl Entry {
    /// True for rows of kind `domain`.
    pub fn is_domain(&self) -> bool {
        self.kind == "domain"
    }
}

fn lenient_string<'de, D>(d: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(d)?;
    Ok(match v {
        serde_json::Value::String(s) => s,
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    })
}

/// Package ecosystems understood by [`Blocklist::check_package`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    /// npm: names compared in lower case.
    Npm,
    /// PyPI: names compared after PEP 503 normalisation.
    Pypi,
}

impl FromStr for Ecosystem {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "npm" => Ok(Ecosystem::Npm),
            "pypi" => Ok(Ecosystem::Pypi),
            other => Err(Error::InvalidArgument(format!(
                "unknown package ecosystem {:?}, use \"npm\" or \"pypi\"",
                other
            ))),
        }
    }
}

const EXTENSION_KINDS: [&str; 6] = [
    "chrome_ext",
    "edge_ext",
    "firefox_ext",
    "vscode_ext",
    "openvsx_ext",
    "jetbrains_plugin",
];
const PROCESS_KINDS: [&str; 3] = ["process_cli", "process_mac", "process_win"];

#[derive(Deserialize)]
struct RawFeed {
    #[serde(default, deserialize_with = "lenient_string")]
    product: String,
    #[serde(default, deserialize_with = "lenient_string")]
    version: String,
    #[serde(default)]
    counts: serde_json::Value,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    entries: Vec<Entry>,
}

/// The parsed feed with lookup maps built once, at load time.
///
/// Every `check_*` method is a hash lookup (a few of them for domains, one
/// per label), so a `Blocklist` can sit in a hot path such as a log scanner
/// or a request filter. It is `Send + Sync`; wrap it in an `Arc` to share it.
#[derive(Debug, Clone)]
pub struct Blocklist {
    product: String,
    version: String,
    counts: BTreeMap<String, u64>,
    columns: Vec<String>,
    entries: Vec<Entry>,
    by_domain: HashMap<String, usize>,
    by_extension: HashMap<String, usize>,
    by_process: HashMap<String, usize>,
    by_npm: HashMap<String, usize>,
    by_pypi: HashMap<String, usize>,
    by_ident: HashMap<String, usize>,
    by_ident_lower: HashMap<String, usize>,
    domain_list: Vec<String>,
    agent_type_list: Vec<String>,
    kind_list: Vec<String>,
}

impl Blocklist {
    /// Parse the text of `aab_full.json`.
    pub fn from_json(text: &str) -> Result<Blocklist> {
        let raw: RawFeed = serde_json::from_str(text)?;
        Ok(Blocklist::build(raw))
    }

    /// Parse `aab_full.json` from raw bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Blocklist> {
        let raw: RawFeed = serde_json::from_slice(bytes)?;
        Ok(Blocklist::build(raw))
    }

    /// Parse `aab_full.json` from any reader.
    pub fn from_reader<R: Read>(reader: R) -> Result<Blocklist> {
        let raw: RawFeed = serde_json::from_reader(std::io::BufReader::new(reader))?;
        Ok(Blocklist::build(raw))
    }

    /// Read and parse a local copy of `aab_full.json`.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Blocklist> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|e| {
            Error::other(format!("could not read {}: {}", path.display(), e), e)
        })?;
        Blocklist::from_slice(&bytes)
    }

    fn build(raw: RawFeed) -> Blocklist {
        let mut counts = BTreeMap::new();
        if let serde_json::Value::Object(map) = raw.counts {
            for (k, v) in map {
                if let Some(n) = v.as_u64() {
                    counts.insert(k, n);
                }
            }
        }

        let mut by_domain = HashMap::new();
        let mut by_extension = HashMap::new();
        let mut by_process = HashMap::new();
        let mut by_npm = HashMap::new();
        let mut by_pypi = HashMap::new();
        let mut by_ident = HashMap::new();
        let mut by_ident_lower = HashMap::new();
        let mut domain_list = Vec::new();
        let mut agent_types = BTreeSet::new();
        let mut kinds = BTreeSet::new();

        for (i, e) in raw.entries.iter().enumerate() {
            let ident = e.ident.trim();
            if !e.agent_type.is_empty() {
                agent_types.insert(e.agent_type.clone());
            }
            if !e.kind.is_empty() {
                kinds.insert(e.kind.clone());
            }
            if ident.is_empty() {
                continue;
            }
            let lower = ident.to_lowercase();
            by_ident.entry(ident.to_string()).or_insert(i);
            by_ident_lower.entry(lower.clone()).or_insert(i);

            let kind = e.kind.as_str();
            if kind == "domain" {
                let key = lower.trim_end_matches('.').to_string();
                if !key.is_empty() && !by_domain.contains_key(&key) {
                    by_domain.insert(key.clone(), i);
                    domain_list.push(key);
                }
            } else if EXTENSION_KINDS.contains(&kind) {
                by_extension.entry(lower).or_insert(i);
            } else if PROCESS_KINDS.contains(&kind) {
                if let Some(stem) = strip_exe(&lower) {
                    by_process.entry(stem.to_string()).or_insert(i);
                }
                by_process.entry(lower).or_insert(i);
            } else if kind == "npm" {
                by_npm.entry(lower).or_insert(i);
            } else if kind == "pypi" {
                by_pypi.entry(pep503(ident)).or_insert(i);
            }
        }

        Blocklist {
            product: raw.product,
            version: raw.version,
            counts,
            columns: raw.columns,
            entries: raw.entries,
            by_domain,
            by_extension,
            by_process,
            by_npm,
            by_pypi,
            by_ident,
            by_ident_lower,
            domain_list,
            agent_type_list: agent_types.into_iter().collect(),
            kind_list: kinds.into_iter().collect(),
        }
    }

    /// Product name from the file (`AI Agent Blocklist`).
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Feed version string. It changes with every daily rebuild.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Counts from the file, for example `domains` or `npm_packages`.
    pub fn counts(&self) -> &BTreeMap<String, u64> {
        &self.counts
    }

    /// One count by key.
    pub fn count(&self, key: &str) -> Option<u64> {
        self.counts.get(key).copied()
    }

    /// Column names in CSV order.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// All rows, in file order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the file had no rows.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Match a host name or a URL against the domain rows.
    ///
    /// The input is normalised with [`normalize_host`]. The host itself and
    /// each parent domain are tried, so `api.example-agent.ai` matches a row
    /// for `example-agent.ai`, while `notexample-agent.ai` does not.
    pub fn check_domain(&self, host_or_url: &str) -> Option<&Entry> {
        let host = normalize_host(host_or_url)?;
        let mut rest = host.as_str();
        loop {
            if let Some(&i) = self.by_domain.get(rest) {
                return Some(&self.entries[i]);
            }
            let dot = rest.find('.')?;
            rest = &rest[dot + 1..];
        }
    }

    /// Exact, case-insensitive match over browser extension IDs (Chrome,
    /// Edge, Firefox) and editor plugin IDs (VS Code, Open VSX, JetBrains).
    pub fn check_extension(&self, id: &str) -> Option<&Entry> {
        let key = id.trim().to_lowercase();
        self.by_extension.get(&key).map(|&i| &self.entries[i])
    }

    /// Case-insensitive match over process and command names for Windows,
    /// macOS and the command line. A full path is reduced to its file name,
    /// and `name.exe` and `name` match each other.
    pub fn check_process(&self, name: &str) -> Option<&Entry> {
        let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
        let key = base.trim().to_lowercase();
        if key.is_empty() {
            return None;
        }
        if let Some(&i) = self.by_process.get(&key) {
            return Some(&self.entries[i]);
        }
        strip_exe(&key)
            .and_then(|stem| self.by_process.get(stem))
            .map(|&i| &self.entries[i])
    }

    /// Match an npm or PyPI package name.
    ///
    /// npm names compare in lower case. PyPI names compare after PEP 503
    /// normalisation, so `Demo_MCP.Server` and `demo-mcp-server` are equal.
    pub fn check_package(&self, ecosystem: Ecosystem, name: &str) -> Option<&Entry> {
        let found = match ecosystem {
            Ecosystem::Npm => self.by_npm.get(&name.trim().to_lowercase()),
            Ecosystem::Pypi => self.by_pypi.get(&pep503(name)),
        };
        found.map(|&i| &self.entries[i])
    }

    /// Match anything: domain rules first, then the identifier exactly as
    /// written, then the identifier in lower case.
    pub fn check(&self, identifier: &str) -> Option<&Entry> {
        if let Some(e) = self.check_domain(identifier) {
            return Some(e);
        }
        let t = identifier.trim();
        if let Some(&i) = self.by_ident.get(t) {
            return Some(&self.entries[i]);
        }
        self.by_ident_lower
            .get(&t.to_lowercase())
            .map(|&i| &self.entries[i])
    }

    /// Rows that match every given field. `None` (or an empty string) means
    /// "any value". Comparison ignores case. Rows keep their file order.
    pub fn filter(
        &self,
        agent_type: Option<&str>,
        kind: Option<&str>,
        risk_grade: Option<&str>,
    ) -> Vec<&Entry> {
        let want = |v: Option<&str>| {
            v.map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
        };
        let (a, k, r) = (want(agent_type), want(kind), want(risk_grade));
        let same = |field: &str, wanted: &Option<String>| match wanted {
            None => true,
            Some(w) => field.to_lowercase() == *w,
        };
        self.entries
            .iter()
            .filter(|e| same(&e.agent_type, &a) && same(&e.kind, &k) && same(&e.risk_grade, &r))
            .collect()
    }

    /// Distinct listed domains in lower case, in file order.
    pub fn domains(&self) -> &[String] {
        &self.domain_list
    }

    /// Distinct agent types, sorted.
    pub fn agent_types(&self) -> &[String] {
        &self.agent_type_list
    }

    /// Distinct kinds, sorted.
    pub fn kinds(&self) -> &[String] {
        &self.kind_list
    }

    /// Distinct identifiers of the given kinds, in file order.
    ///
    /// Handy for writing a policy, for example every `chrome_ext` ID.
    pub fn idents_of(&self, kinds: &[&str]) -> Vec<&str> {
        let mut seen = HashSet::new();
        self.entries
            .iter()
            .filter(|e| kinds.contains(&e.kind.as_str()))
            .map(|e| e.ident.as_str())
            .filter(|id| seen.insert(*id))
            .collect()
    }
}

fn strip_exe(lower: &str) -> Option<&str> {
    lower.strip_suffix(".exe").filter(|s| !s.is_empty())
}

/// Reduce a URL or host to a bare, lower case host name.
///
/// Drops the scheme, user info, port, path, query and fragment and any
/// trailing dot. Returns `None` when nothing is left.
///
/// ```
/// use aiagentblocklist::normalize_host;
/// assert_eq!(
///     normalize_host("HTTPS://user@API.Example-Agent.AI:8443/run?x=1#top").as_deref(),
///     Some("api.example-agent.ai")
/// );
/// assert_eq!(normalize_host("sample-browser.app.").as_deref(), Some("sample-browser.app"));
/// ```
pub fn normalize_host(input: &str) -> Option<String> {
    let mut s = input.trim();
    if let Some(i) = s.find("://") {
        let scheme = &s[..i];
        if !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        {
            s = &s[i + 3..];
        }
    } else if let Some(rest) = s.strip_prefix("//") {
        s = rest;
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    if let Some(rest) = s.strip_prefix('[') {
        s = match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest,
        };
    } else if let Some(i) = s.find(':') {
        s = &s[..i];
    }
    let host = s.trim().to_lowercase();
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// PEP 503 name normalisation: lower case, and every run of `-`, `_` or
/// `.` becomes a single `-`.
///
/// ```
/// assert_eq!(aiagentblocklist::pep503("DEMO__mcp..server"), "demo-mcp-server");
/// ```
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.trim().chars() {
        if c == '-' || c == '_' || c == '.' {
            if !in_run {
                out.push('-');
                in_run = true;
            }
        } else {
            in_run = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}
