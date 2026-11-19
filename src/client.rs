//! Blocking download client for the subscriber feed.

use crate::blocklist::Blocklist;
use crate::error::{Error, Result};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Version of this crate.
pub const VERSION: &str = "1.0.0";
/// Default site root.
pub const DEFAULT_BASE_URL: &str = "https://www.aiagentblocklist.com";
/// Environment variable read when no token is passed in.
pub const TOKEN_ENV: &str = "AIAGENTBLOCKLIST_TOKEN";
/// User-Agent sent with every request unless you set your own.
pub const DEFAULT_USER_AGENT: &str =
    "aiagentblocklist-rust/1.0.0 (+https://www.aiagentblocklist.com)";
/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Every file published for a subscription, in the order `sync` fetches them.
pub const FILES: [&str; 19] = [
    "aab_full.csv",
    "aab_full.json",
    "domains.txt",
    "firewall_edl.txt",
    "hosts.txt",
    "proxy.pac",
    "dns_rpz.zone",
    "chrome_extension_blocklist.json",
    "edge_extension_blocklist.json",
    "chrome_edge_extension_blocklist.reg",
    "chrome_edge_extensions.mobileconfig",
    "firefox_extension_ids.txt",
    "macos_bundle_ids.txt",
    "windows_package_ids.txt",
    "process_names.txt",
    "npm_packages.txt",
    "pypi_packages.txt",
    "counts.json",
    "README.txt",
];

const EXTENSIONS: [&str; 7] = ["csv", "json", "txt", "pac", "zone", "reg", "mobileconfig"];

/// Check a token: exactly 32 ASCII letters and digits.
pub fn validate_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Err(Error::Token(format!(
            "no token given and {} is not set",
            TOKEN_ENV
        )));
    }
    if token.len() != 32 || !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(Error::Token(format!(
            "expected 32 letters and digits, got {} characters",
            token.chars().count()
        )));
    }
    Ok(())
}

/// Check a feed file name: a letter or digit, then letters, digits or
/// underscores, then one of the known extensions.
pub fn validate_file_name(name: &str) -> Result<()> {
    let bad = || {
        Error::InvalidArgument(format!(
            "{:?} is not a valid feed file name",
            name
        ))
    };
    let (stem, ext) = name.split_once('.').ok_or_else(bad)?;
    let mut chars = stem.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !first_ok || !rest_ok || !EXTENSIONS.contains(&ext) {
        return Err(bad());
    }
    Ok(())
}

/// Strip `W/`, quotes and a `-gzip` suffix so two ETags can be compared.
pub fn bare_etag(tag: &str) -> &str {
    let mut t = tag.trim();
    if t.len() >= 2 && t[..2].eq_ignore_ascii_case("w/") {
        t = &t[2..];
    }
    let t = t.trim_matches('"');
    t.strip_suffix("-gzip").unwrap_or(t)
}

/// Options for [`Client`]. Start with [`Client::builder`].
#[derive(Clone)]
pub struct ClientBuilder {
    token: Option<String>,
    base_url: String,
    timeout: Duration,
    user_agent: String,
    proxy_from_env: bool,
    agent: Option<ureq::Agent>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        ClientBuilder {
            token: None,
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            proxy_from_env: true,
            agent: None,
        }
    }
}

impl ClientBuilder {
    /// The 32 character download token. Without it, `build` reads
    /// `AIAGENTBLOCKLIST_TOKEN`.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Site root, for a mirror or a test server.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Overall timeout per request. Default 30 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the User-Agent header.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Read `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` from the environment.
    /// On by default. Ignored when you pass your own agent.
    pub fn proxy_from_env(mut self, on: bool) -> Self {
        self.proxy_from_env = on;
        self
    }

    /// Bring your own `ureq::Agent` (custom TLS roots, a fixed proxy).
    /// The timeout option is then up to that agent.
    pub fn agent(mut self, agent: ureq::Agent) -> Self {
        self.agent = Some(agent);
        self
    }

    /// Validate the token and create the client. No request is sent.
    pub fn build(self) -> Result<Client> {
        let token = match self.token {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => std::env::var(TOKEN_ENV)
                .map(|v| v.trim().to_string())
                .unwrap_or_default(),
        };
        validate_token(&token)?;
        let agent = match self.agent {
            Some(a) => a,
            None => ureq::AgentBuilder::new()
                .timeout(self.timeout)
                .try_proxy_from_env(self.proxy_from_env)
                .build(),
        };
        Ok(Client {
            token,
            base_url: self.base_url.trim_end_matches('/').to_string(),
            user_agent: self.user_agent,
            agent,
        })
    }
}

/// Downloads feed files for one subscription.
///
/// The client is cheap to clone and safe to share between threads.
#[derive(Clone)]
pub struct Client {
    token: String,
    base_url: String,
    user_agent: String,
    agent: ureq::Agent,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("token", &"<hidden>")
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

enum Fetched {
    Body(Vec<u8>, Option<String>),
    NotModified,
}

impl Client {
    /// Client with an explicit token and default options. An empty string
    /// falls back to `AIAGENTBLOCKLIST_TOKEN`.
    pub fn new(token: impl Into<String>) -> Result<Client> {
        ClientBuilder::default().token(token).build()
    }

    /// Client with the token from `AIAGENTBLOCKLIST_TOKEN`.
    pub fn from_env() -> Result<Client> {
        ClientBuilder::default().build()
    }

    /// Start a [`ClientBuilder`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// The site root in use, without a trailing slash.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Full download URL of one file. Rejects names that are not feed file
    /// names. The URL contains the token, so keep it out of logs.
    pub fn file_url(&self, name: &str) -> Result<String> {
        validate_file_name(name)?;
        Ok(format!("{}/download/{}/{}", self.base_url, self.token, name))
    }

    /// Download one file and return its bytes.
    pub fn download(&self, name: &str) -> Result<Vec<u8>> {
        match self.fetch(name, None)? {
            Fetched::Body(body, _) => Ok(body),
            Fetched::NotModified => Err(Error::Http {
                status: 304,
                file: name.to_string(),
            }),
        }
    }

    /// Download one file and return it as UTF-8 text.
    pub fn download_string(&self, name: &str) -> Result<String> {
        let body = self.download(name)?;
        String::from_utf8(body).map_err(|e| {
            Error::other(format!("{} is not valid UTF-8", name), e)
        })
    }

    /// Conditional download into `path`.
    ///
    /// The ETag is kept next to the file in `<path>.etag`. When the server
    /// answers 304, or sends the same ETag again, the file stays untouched
    /// and the result is `false`. New content is written to a temporary file
    /// in the same directory and renamed over `path`, so readers never see a
    /// half-written list. Returns `true` when the file changed.
    pub fn download_to(&self, name: &str, path: impl AsRef<Path>) -> Result<bool> {
        validate_file_name(name)?;
        let path = path.as_ref();
        let sidecar = sidecar_path(path);
        let stored = if path.is_file() {
            fs::read_to_string(&sidecar)
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        let condition = if stored.is_empty() { None } else { Some(stored.as_str()) };

        let (body, etag) = match self.fetch(name, condition)? {
            Fetched::NotModified => return Ok(false),
            Fetched::Body(body, etag) => (body, etag.unwrap_or_default()),
        };
        if !stored.is_empty() && !etag.is_empty() && bare_etag(&etag) == bare_etag(&stored) {
            return Ok(false);
        }

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        write_atomic(path, &body)?;
        fs::write(&sidecar, etag.as_bytes())?;
        Ok(true)
    }

    /// Run [`Client::download_to`] for each name into `dir`. An empty slice
    /// means every file in [`FILES`]. Returns `(name, changed)` pairs in the
    /// order requested and stops at the first error.
    pub fn sync(&self, dir: impl AsRef<Path>, names: &[&str]) -> Result<Vec<(String, bool)>> {
        let dir = dir.as_ref();
        let list: &[&str] = if names.is_empty() { &FILES } else { names };
        for name in list {
            validate_file_name(name)?;
        }
        fs::create_dir_all(dir)?;
        let mut out = Vec::with_capacity(list.len());
        for name in list {
            let changed = self.download_to(name, dir.join(name))?;
            out.push((name.to_string(), changed));
        }
        Ok(out)
    }

    /// Shorthand for `sync(dir, &[])`: every file.
    pub fn sync_all(&self, dir: impl AsRef<Path>) -> Result<Vec<(String, bool)>> {
        self.sync(dir, &[])
    }

    /// Download `aab_full.json` and parse it.
    pub fn load_blocklist(&self) -> Result<Blocklist> {
        let body = self.download("aab_full.json")?;
        Blocklist::from_slice(&body)
    }

    fn fetch(&self, name: &str, if_none_match: Option<&str>) -> Result<Fetched> {
        let url = self.file_url(name)?;
        let mut req = self
            .agent
            .get(&url)
            .set("User-Agent", &self.user_agent)
            .set("Accept", "*/*");
        if let Some(tag) = if_none_match {
            req = req.set("If-None-Match", tag);
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) => return Err(status_error(code, name)),
            Err(ureq::Error::Transport(t)) => {
                // The transport error's Display includes the URL, and with it
                // the token, so only kind and detail are kept.
                let mut msg = format!("network error while fetching {}: {}", name, t.kind());
                if let Some(detail) = t.message() {
                    msg.push_str(": ");
                    msg.push_str(detail);
                }
                if let Some(cause) = std::error::Error::source(&t) {
                    msg.push_str(" (");
                    msg.push_str(&cause.to_string());
                    msg.push(')');
                }
                return Err(Error::plain(msg));
            }
        };
        let status = resp.status();
        if status == 304 {
            return Ok(Fetched::NotModified);
        }
        if !(200..300).contains(&status) {
            return Err(status_error(status, name));
        }
        let etag = resp.header("ETag").map(|s| s.trim().to_string());
        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .map_err(|e| Error::other(format!("reading {} failed: {}", name, e), e))?;
        Ok(Fetched::Body(body, etag))
    }
}

fn status_error(code: u16, name: &str) -> Error {
    let file = name.to_string();
    match code {
        404 => Error::NotFound { file },
        403 => Error::AccessEnded { file },
        status => Error::Http { status, file },
    }
}

/// `<path>.etag`
pub(crate) fn sidecar_path(path: &Path) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(".etag");
    PathBuf::from(s)
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_atomic(path: &Path, body: &[u8]) -> Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut tmp: OsString = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}{}{}", std::process::id(), nanos, n));
    let tmp = PathBuf::from(tmp);

    let result = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(body)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        // Leave nothing half written behind: the temporary file is ours.
        let _ = fs::remove_file(&tmp);
        Error::other(format!("could not write {}: {}", path.display(), e), e)
    })
}
