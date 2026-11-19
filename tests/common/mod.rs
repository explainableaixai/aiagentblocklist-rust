//! A tiny HTTP/1.1 server on 127.0.0.1 for offline tests (std only).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

pub const TOKEN: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz012345";
pub const FIXTURE: &str = include_str!("../fixtures/aab_full.json");

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// Header names in lower case.
    pub headers: HashMap<String, String>,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn ok(body: impl Into<Vec<u8>>) -> Reply {
        Reply { status: 200, headers: Vec::new(), body: body.into() }
    }
    pub fn status(status: u16) -> Reply {
        Reply { status, headers: Vec::new(), body: Vec::new() }
    }
    pub fn etag(mut self, tag: &str) -> Reply {
        self.headers.push(("ETag".into(), tag.into()));
        self
    }
}

pub struct TestServer {
    pub base: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl TestServer {
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// Start a server; `handler` gets every request and its index (0 based).
pub fn serve<F>(handler: F) -> TestServer
where
    F: Fn(usize, &Seen) -> Reply + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    let counter = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            if reader.read_line(&mut first).unwrap_or(0) == 0 {
                continue;
            }
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let mut headers = HashMap::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }
            let req = Seen { method, path, headers };
            seen2.lock().unwrap().push(req.clone());
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let reply = handler(n, &req);
            let reason = match reply.status {
                200 => "OK",
                304 => "Not Modified",
                403 => "Forbidden",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let mut head = format!("HTTP/1.1 {} {}\r\nConnection: close\r\n", reply.status, reason);
            for (k, v) in &reply.headers {
                head.push_str(&format!("{}: {}\r\n", k, v));
            }
            if reply.status != 304 {
                head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            if reply.status != 304 {
                let _ = stream.write_all(&reply.body);
            }
            let _ = stream.flush();
        }
    });
    TestServer { base, seen }
}

/// Client pointed at a test server, with env proxies switched off.
pub fn client_for(server: &TestServer) -> aiagentblocklist::Client {
    aiagentblocklist::Client::builder()
        .token(TOKEN)
        .base_url(server.base.clone())
        .proxy_from_env(false)
        .build()
        .expect("client")
}

/// A fresh directory under the system temp dir. Tests never remove it.
pub fn scratch_dir(label: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "aab-rust-test-{}-{}-{}-{}",
        label,
        std::process::id(),
        nanos,
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
