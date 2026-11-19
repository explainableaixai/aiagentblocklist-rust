//! The environment variable fallback. Kept in its own test binary because it
//! changes process-wide state.

use aiagentblocklist::{Client, Error, TOKEN_ENV};

#[test]
fn token_from_environment() {
    let token = "ZyXwVuTsRqPoNmLkJiHgFeDcBa987654";

    std::env::remove_var(TOKEN_ENV);
    assert!(matches!(Client::from_env(), Err(Error::Token(_))));

    std::env::set_var(TOKEN_ENV, token);
    let c = Client::from_env().expect("token from env");
    assert!(c.file_url("domains.txt").unwrap().contains(token));

    // An empty argument falls back to the variable too.
    assert!(Client::new("").is_ok());
    // An explicit argument wins over the variable.
    let other = "0123456789abcdefghijABCDEFGHIJkl";
    assert!(Client::new(other).unwrap().file_url("hosts.txt").unwrap().contains(other));

    std::env::set_var(TOKEN_ENV, "not-a-token");
    assert!(matches!(Client::from_env(), Err(Error::Token(_))));
    std::env::remove_var(TOKEN_ENV);
}
