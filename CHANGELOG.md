# Changelog

All notable changes to the `aiagentblocklist` crate are listed here.

## 1.0.0

First release.

- Blocking `Client` for the subscriber download links at `https://www.aiagentblocklist.com/download/<TOKEN>/<file>`, built on `ureq`.
- Token from `Client::new` or the `AIAGENTBLOCKLIST_TOKEN` environment variable, checked locally (32 letters and digits) before any request.
- `ClientBuilder` options: `base_url`, `timeout` (30 seconds by default), `user_agent`, `proxy_from_env` and a custom `ureq::Agent`.
- `file_url`, `download`, `download_string`, `download_to` (conditional GET with a `<path>.etag` sidecar and atomic replace), `sync`, `sync_all` and `load_blocklist`.
- `Blocklist` with `from_file`, `from_json`, `from_slice` and `from_reader`, lookup maps built once at load time, and `check_domain`, `check_extension`, `check_process`, `check_package`, `check`, `filter`, `domains`, `agent_types`, `kinds` and `idents_of`.
- `Entry` struct with the ten feed columns, `serde` support on both sides.
- `Error` enum: `Token`, `InvalidArgument`, `NotFound` (404), `AccessEnded` (403), `Http` and `Other`, with `status()` and `message()`. Messages never contain the token.
- Helpers `normalize_host`, `pep503`, `bare_etag`, `validate_token` and `validate_file_name`.
- Examples: the `aab` command line tool and the `scan_log` log matcher.
