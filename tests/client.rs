//! HTTP behaviour against a local test server. No outside network.

mod common;

use aiagentblocklist::{bare_etag, validate_file_name, Client, Error, DEFAULT_USER_AGENT, FILES};
use common::{client_for, scratch_dir, serve, Reply, FIXTURE, TOKEN};
use std::fs;
use std::time::Duration;

#[test]
fn token_must_be_32_alphanumerics() {
    for bad in ["short", "AbCdEfGhIjKlMnOpQrStUvWxYz01234-", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456"] {
        let err = Client::new(bad).unwrap_err();
        assert!(matches!(err, Error::Token(_)), "{}", bad);
        assert_eq!(err.status(), 0);
        assert!(!err.to_string().contains(bad), "token echoed in message");
    }
    assert!(Client::new(TOKEN).is_ok());
    assert!(Client::new(format!("  {}\n", TOKEN)).is_ok());
}

#[test]
fn file_names_are_checked() {
    for good in FILES {
        assert!(validate_file_name(good).is_ok(), "{}", good);
    }
    for bad in [
        "../etc/passwd",
        "aab_full.exe",
        "_x.txt",
        "a.b.txt",
        "domains",
        "",
        "domains.txt/",
        "dom ains.txt",
        "hosts.TXT",
    ] {
        assert!(matches!(validate_file_name(bad), Err(Error::InvalidArgument(_))), "{}", bad);
    }
}

#[test]
fn file_url_layout() {
    let c = Client::builder()
        .token(TOKEN)
        .base_url("https://mirror.example.test/")
        .build()
        .unwrap();
    assert_eq!(
        c.file_url("domains.txt").unwrap(),
        format!("https://mirror.example.test/download/{}/domains.txt", TOKEN)
    );
    assert!(c.file_url("../secret.txt").is_err());
    let default = Client::new(TOKEN).unwrap();
    assert!(default.file_url("hosts.txt").unwrap().starts_with("https://www.aiagentblocklist.com/download/"));
    assert!(!format!("{:?}", default).contains(TOKEN));
}

#[test]
fn bare_etag_forms() {
    assert_eq!(bare_etag("W/\"abc-gzip\""), "abc");
    assert_eq!(bare_etag("w/\"abc\""), "abc");
    assert_eq!(bare_etag("\"abc\""), "abc");
    assert_eq!(bare_etag(" abc-gzip "), "abc");
    assert_eq!(bare_etag("\"abc-br\""), "abc-br");
}

#[test]
fn download_sends_user_agent_and_returns_body() {
    let server = serve(|_, _| Reply::ok("example-agent.ai\n"));
    let c = client_for(&server);
    let body = c.download("domains.txt").unwrap();
    assert_eq!(body, b"example-agent.ai\n");
    let reqs = server.requests();
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, format!("/download/{}/domains.txt", TOKEN));
    assert_eq!(reqs[0].headers["user-agent"], DEFAULT_USER_AGENT);
    assert_eq!(DEFAULT_USER_AGENT, "aiagentblocklist-rust/1.0.0 (+https://www.aiagentblocklist.com)");
}

#[test]
fn custom_user_agent() {
    let server = serve(|_, _| Reply::ok("x"));
    let c = Client::builder()
        .token(TOKEN)
        .base_url(server.base.clone())
        .user_agent("nightly-sync/2")
        .timeout(Duration::from_secs(5))
        .proxy_from_env(false)
        .build()
        .unwrap();
    assert_eq!(c.download_string("README.txt").unwrap(), "x");
    assert_eq!(server.requests()[0].headers["user-agent"], "nightly-sync/2");
}

#[test]
fn status_codes_map_to_errors() {
    let server = serve(|_, req| {
        if req.path.ends_with("/firewall_edl.txt") {
            Reply::status(404)
        } else if req.path.ends_with("/hosts.txt") {
            Reply::status(403)
        } else {
            Reply::status(500)
        }
    });
    let c = client_for(&server);

    let e = c.download("firewall_edl.txt").unwrap_err();
    assert!(matches!(e, Error::NotFound { ref file } if file == "firewall_edl.txt"));
    assert_eq!(e.status(), 404);

    let e = c.download("hosts.txt").unwrap_err();
    assert!(matches!(e, Error::AccessEnded { .. }));
    assert_eq!(e.status(), 403);
    assert!(e.message().contains("ended or is paused"));

    let e = c.download("proxy.pac").unwrap_err();
    assert!(matches!(e, Error::Http { status: 500, .. }));
    assert_eq!(e.status(), 500);

    for e in [c.download("firewall_edl.txt"), c.download("hosts.txt"), c.download("proxy.pac")] {
        assert!(!e.unwrap_err().to_string().contains(TOKEN));
    }
}

#[test]
fn network_errors_are_wrapped_without_token() {
    // Bind and release a port so nothing listens on it.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let c = Client::builder()
        .token(TOKEN)
        .base_url(format!("http://127.0.0.1:{}", port))
        .timeout(Duration::from_secs(5))
        .proxy_from_env(false)
        .build()
        .unwrap();
    let e = c.download("domains.txt").unwrap_err();
    assert!(matches!(e, Error::Other { .. }));
    assert_eq!(e.status(), 0);
    assert!(!e.to_string().contains(TOKEN));
    assert!(e.to_string().contains("domains.txt"));
}

#[test]
fn download_to_uses_the_etag_sidecar() {
    let server = serve(|n, _| match n {
        0 => Reply::ok("one\n").etag("W/\"v1-gzip\""),
        1 => Reply::status(304),
        // A 200 that carries the same bare tag counts as unchanged.
        2 => Reply::ok("not written\n").etag("\"v1\""),
        3 => Reply::ok("two\n").etag("\"v2\""),
        4 => Reply::ok("three\n"),
        _ => Reply::ok("four\n"),
    });
    let c = client_for(&server);
    let dir = scratch_dir("etag");
    let path = dir.join("nested").join("domains.txt");
    let sidecar = dir.join("nested").join("domains.txt.etag");

    assert!(c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");
    assert_eq!(fs::read_to_string(&sidecar).unwrap(), "W/\"v1-gzip\"");

    assert!(!c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");

    assert!(!c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), "one\n");

    assert!(c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), "two\n");
    assert_eq!(fs::read_to_string(&sidecar).unwrap(), "\"v2\"");

    // No ETag on the answer: the sidecar is emptied, never removed.
    assert!(c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&sidecar).unwrap(), "");

    assert!(c.download_to("domains.txt", &path).unwrap());
    assert_eq!(fs::read_to_string(&path).unwrap(), "four\n");

    let reqs = server.requests();
    assert_eq!(reqs[0].headers.get("if-none-match"), None);
    assert_eq!(reqs[1].headers["if-none-match"], "W/\"v1-gzip\"");
    assert_eq!(reqs[2].headers["if-none-match"], "W/\"v1-gzip\"");
    assert_eq!(reqs[3].headers["if-none-match"], "W/\"v1-gzip\"");
    assert_eq!(reqs[4].headers["if-none-match"], "\"v2\"");
    assert_eq!(reqs[5].headers.get("if-none-match"), None);

    // No temp files left next to the target.
    let names: Vec<String> = fs::read_dir(dir.join("nested"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{:?}", names);
}

#[test]
fn sidecar_without_file_is_ignored() {
    let server = serve(|_, _| Reply::ok("fresh\n").etag("\"v9\""));
    let c = client_for(&server);
    let dir = scratch_dir("orphan");
    fs::write(dir.join("hosts.txt.etag"), "\"v9\"").unwrap();
    assert!(c.download_to("hosts.txt", dir.join("hosts.txt")).unwrap());
    assert_eq!(server.requests()[0].headers.get("if-none-match"), None);
    assert_eq!(fs::read_to_string(dir.join("hosts.txt")).unwrap(), "fresh\n");
}

#[test]
fn sync_returns_changes_in_order() {
    let server = serve(|_, req| {
        if req.headers.contains_key("if-none-match") {
            Reply::status(304)
        } else {
            let name = req.path.rsplit('/').next().unwrap().to_string();
            Reply::ok(format!("body of {}\n", name)).etag(&format!("\"{}-1\"", name))
        }
    });
    let c = client_for(&server);
    let dir = scratch_dir("sync");
    let first = c.sync(&dir, &["hosts.txt", "domains.txt"]).unwrap();
    assert_eq!(first, vec![("hosts.txt".to_string(), true), ("domains.txt".to_string(), true)]);
    let second = c.sync(&dir, &["hosts.txt", "domains.txt"]).unwrap();
    assert_eq!(second, vec![("hosts.txt".to_string(), false), ("domains.txt".to_string(), false)]);
    assert_eq!(fs::read_to_string(dir.join("domains.txt")).unwrap(), "body of domains.txt\n");

    let all = c.sync_all(scratch_dir("sync-all")).unwrap();
    assert_eq!(all.len(), 19);
    assert_eq!(all[0].0, "aab_full.csv");
    assert!(all.iter().all(|(_, changed)| *changed));

    assert!(matches!(c.sync(&dir, &["../x.txt"]), Err(Error::InvalidArgument(_))));
}

#[test]
fn sync_stops_on_access_ended() {
    let server = serve(|_, _| Reply::status(403));
    let c = client_for(&server);
    let e = c.sync(scratch_dir("ended"), &["domains.txt", "hosts.txt"]).unwrap_err();
    assert!(matches!(e, Error::AccessEnded { .. }));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn load_blocklist_over_http() {
    let server = serve(|_, req| {
        if req.path.ends_with("/aab_full.json") {
            Reply::ok(FIXTURE).etag("\"feed\"")
        } else {
            Reply::status(404)
        }
    });
    let list = client_for(&server).load_blocklist().unwrap();
    assert_eq!(list.version(), "test-1");
    assert!(list.check_domain("api.example-agent.ai").is_some());
}
