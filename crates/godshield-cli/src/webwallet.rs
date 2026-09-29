// crates/godshield-cli/src/webwallet.rs
//
// ═══════════════════════════════════════════════════════════════════════
// Local browser wallet — `godshield wallet open`
//
// A wallet page served by this process on the user's own machine. The
// page talks only to this process; this process talks to a NEV369 node.
// Signing happens here, in the same Rust code the node verifies with, so
// the key never reaches the browser and the format cannot drift.
//
// Why not a website: a Dilithium5 key cannot be used from browser
// JavaScript without a WebAssembly build of the signer (not yet shipped),
// and a hosted site that signs on its server would hold everyone's keys.
//
// A local signing server is itself a target — any web page the user
// visits can send requests to 127.0.0.1. So:
//
//   • Bound to 127.0.0.1 by default. Nothing off the machine can connect.
//   • Every /api request needs a 256-bit token that exists only in the URL
//     printed to the terminal (in the #fragment, so it is never sent in a
//     request line or logged). Compared in constant time.
//   • The Host header must name this server — defeats DNS rebinding, where
//     an attacker's domain is pointed at 127.0.0.1.
//   • Any Origin header must be this server's own origin, so another site
//     cannot drive the API even if it guessed the port.
//   • The key is decrypted per send, used for one signature, and dropped.
//     Passwords and share contents are zeroed after use.
//   • Strict Content-Security-Policy; the page loads nothing but fonts.
// ═══════════════════════════════════════════════════════════════════════

use crate::keyfile::WalletFile;
use crate::send::{self, fetch_account, Transfer};
use anyhow::{anyhow, bail, Context};
use nevaeh_vault::{TimeLockedVault, VaultShare};
use rand::RngCore;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const UI: &str = include_str!("wallet_ui.html");
const MAX_BODY: usize = 1024 * 1024;
const MAX_HEADER_LINES: usize = 100;
const CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; \
    style-src 'unsafe-inline' https://fonts.googleapis.com; \
    font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub enum KeySource {
    Wallet(WalletFile),
    Vault(TimeLockedVault),
}

pub struct WalletServer {
    source: KeySource,
    address: String,
    label: String,
    node: String,
    explorer: String,
    bind: String,
    port: u16,
    token: String,
    allowed_hosts: Vec<String>,
}

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Zeroizing<Vec<u8>>,
}

type Response = (u16, &'static str, Vec<u8>);

#[derive(Deserialize)]
struct SendRequest {
    to: String,
    amount: String,
    #[serde(default)]
    fee: String,
    #[serde(default)]
    memo: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    shares: Vec<String>,
}

impl WalletServer {
    pub fn new(
        source: KeySource,
        address: String,
        label: String,
        node: String,
        explorer: String,
        bind: String,
        port: u16,
    ) -> Self {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let mut allowed_hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        if !is_loopback(&bind) {
            allowed_hosts.push(format!("{bind}:{port}"));
            // ChromeOS reaches its Linux container under this name.
            allowed_hosts.push(format!("penguin.linux.test:{port}"));
        }
        Self {
            source,
            address,
            label,
            node: node.trim_end_matches('/').to_string(),
            explorer,
            bind,
            port,
            token,
            allowed_hosts,
        }
    }

    /// The link to open. The token rides in the #fragment, which browsers
    /// never send to the server.
    pub fn url(&self) -> String {
        // Listening on every interface includes loopback, and 0.0.0.0 is
        // not an address a browser can open.
        let host = if is_loopback(&self.bind) || is_wildcard(&self.bind) {
            "127.0.0.1"
        } else {
            self.bind.as_str()
        };
        format!("http://{host}:{}/#t={}", self.port, self.token)
    }

    /// The same session under the name ChromeOS gives its Linux container,
    /// for when the wallet listens beyond loopback.
    pub fn chromeos_url(&self) -> Option<String> {
        self.exposed_beyond_this_machine()
            .then(|| format!("http://penguin.linux.test:{}/#t={}", self.port, self.token))
    }

    pub fn exposed_beyond_this_machine(&self) -> bool {
        !is_loopback(&self.bind)
    }

    /// Serve until the process is stopped. One connection at a time: this
    /// is a single-user wallet, and serial handling means two sends can
    /// never race each other for the same nonce.
    pub fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind((self.bind.as_str(), self.port)).with_context(|| {
            format!(
                "could not listen on {}:{} — is the wallet already open? Try --port",
                self.bind, self.port
            )
        })?;
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    if let Err(e) = self.handle(s) {
                        eprintln!("    wallet: {e:#}");
                    }
                }
                Err(e) => eprintln!("    wallet: connection failed: {e}"),
            }
        }
        Ok(())
    }

    fn handle(&self, mut stream: TcpStream) -> anyhow::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(15)))?;
        let req = match read_request(&stream) {
            Ok(r) => r,
            Err(_) => return Ok(()), // malformed or timed out — drop quietly
        };
        let (status, ctype, body) = self.route(&req);
        write_response(&mut stream, status, ctype, &body)
    }

    fn route(&self, req: &Request) -> Response {
        let host = req.headers.get("host").map(String::as_str).unwrap_or("");
        if !self.allowed_hosts.iter().any(|h| h == host) {
            return text(403, "Forbidden: unexpected Host header.");
        }
        if let Some(origin) = req.headers.get("origin") {
            if !self
                .allowed_hosts
                .iter()
                .any(|h| origin.as_str() == format!("http://{h}"))
            {
                return text(403, "Forbidden: cross-origin request.");
            }
        }

        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => (200, "text/html; charset=utf-8", UI.as_bytes().to_vec()),
            ("GET", "/favicon.ico") => (204, "text/plain", Vec::new()),
            (method, path) if path.starts_with("/api/") => {
                let token = req
                    .headers
                    .get("x-wallet-token")
                    .map(String::as_str)
                    .unwrap_or("");
                if !ct_eq(token.as_bytes(), self.token.as_bytes()) {
                    return json(
                        401,
                        serde_json::json!({
                            "error": "Open the wallet with the link printed in your terminal."
                        }),
                    );
                }
                match (method, path) {
                    ("GET", "/api/state") => json(200, self.state()),
                    ("GET", "/api/account") => json(200, self.account()),
                    ("POST", "/api/send") => match self.send(&req.body) {
                        Ok(v) => json(200, v),
                        Err(e) => json(400, serde_json::json!({ "error": format!("{e:#}") })),
                    },
                    _ => json(404, serde_json::json!({ "error": "unknown endpoint" })),
                }
            }
            _ => text(404, "Not found"),
        }
    }

    fn state(&self) -> serde_json::Value {
        let (kind, shares_required) = match &self.source {
            KeySource::Wallet(_) => ("wallet", 0u64),
            KeySource::Vault(v) => ("vault", u64::from(v.shares_required)),
        };
        serde_json::json!({
            "address": self.address,
            "label": self.label,
            "kind": kind,
            "shares_required": shares_required,
            "node": self.node,
            "explorer": self.explorer,
        })
    }

    fn account(&self) -> serde_json::Value {
        let base = self.node.as_str();
        match fetch_account(base, &self.address) {
            Ok(a) => {
                let history = send::get_json(&format!(
                    "{base}/address/{}/transactions?limit=50",
                    self.address
                ))
                .unwrap_or(serde_json::Value::Null);
                let height = send::get_json(&format!("{base}/info"))
                    .ok()
                    .and_then(|i| i["height"].as_u64());
                serde_json::json!({
                    "online": true,
                    "balance_units": a.balance,
                    "pending_outgoing_units": a.pending_outgoing,
                    "nonce": a.nonce,
                    "timelocked": a.timelocked,
                    "height": height,
                    "history": history,
                })
            }
            Err(e) => serde_json::json!({ "online": false, "error": format!("{e:#}") }),
        }
    }

    fn send(&self, body: &[u8]) -> anyhow::Result<serde_json::Value> {
        let mut req: SendRequest = serde_json::from_slice(body).context("malformed request")?;
        let result = self.send_inner(&req);
        req.password.zeroize();
        for s in req.shares.iter_mut() {
            s.zeroize();
        }
        result
    }

    fn send_inner(&self, req: &SendRequest) -> anyhow::Result<serde_json::Value> {
        let fee = if req.fee.trim().is_empty() {
            "0"
        } else {
            req.fee.as_str()
        };
        let transfer = Transfer {
            to: req.to.trim().to_string(),
            amount: send::parse_nev(&req.amount).context("amount")?,
            fee: send::parse_nev_allow_zero(fee).context("fee")?,
            memo: req.memo.clone(),
        };
        transfer.validate(&self.address)?;
        let account = fetch_account(&self.node, &self.address)?;
        transfer.check_against(&account)?;

        let kp = match &self.source {
            KeySource::Wallet(w) => {
                if req.password.is_empty() {
                    bail!("enter your wallet password");
                }
                w.open(&req.password)?
            }
            KeySource::Vault(v) => {
                let mut shares = Vec::new();
                for s in &req.shares {
                    shares.push(VaultShare::from_json(s).map_err(|e| anyhow!("share file: {e}"))?);
                }
                send::unlock_vault(v, &shares)?
            }
        };
        if hex::encode(&kp.public_key) != self.address {
            bail!("the unlocked key does not belong to this wallet");
        }
        let (tx, hash) = send::sign_transfer(&kp, &transfer, account.nonce)?;
        drop(kp);

        let accepted = send::submit(&self.node, &tx)?;
        let tx_hash = if accepted.is_empty() { hash } else { accepted };
        Ok(serde_json::json!({ "ok": true, "tx_hash": tx_hash }))
    }
}

fn is_loopback(bind: &str) -> bool {
    bind == "127.0.0.1" || bind == "localhost" || bind == "::1"
}

fn is_wildcard(bind: &str) -> bool {
    bind == "0.0.0.0" || bind == "::"
}

fn read_request(stream: &TcpStream) -> anyhow::Result<Request> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("empty request"))?
        .to_string();
    let target = parts.next().ok_or_else(|| anyhow!("no request target"))?;
    let path = target.split('?').next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut ended = false;
    for _ in 0..MAX_HEADER_LINES {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            ended = true;
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if !ended {
        bail!("headers too long or truncated");
    }

    let len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if len > MAX_BODY {
        bail!("request too large");
    }
    let mut body = Zeroizing::new(vec![0u8; len]);
    reader.read_exact(&mut body[..])?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {ctype}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: {CSP}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn json(status: u16, v: serde_json::Value) -> Response {
    (
        status,
        "application/json",
        serde_json::to_vec(&v).unwrap_or_default(),
    )
}

fn text(status: u16, msg: &str) -> Response {
    (status, "text/plain; charset=utf-8", msg.as_bytes().to_vec())
}

/// Constant-time comparison, so response timing reveals nothing about how
/// much of a guessed token was right.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Best-effort: open the wallet link in the default browser.
pub fn open_browser(url: &str) {
    use std::process::{Command, Stdio};
    // Windows has none of the commands below. rundll32's URL handler opens
    // the default browser and passes the link through untouched (no cmd.exe
    // parsing of & or #).
    #[cfg(windows)]
    {
        let _ = Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        return;
    }
    for cmd in ["xdg-open", "garcon-url-handler", "open"] {
        if Command::new(cmd)
            .arg(url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use godshield_core::GodKeyPair;

    fn server() -> WalletServer {
        let kp = GodKeyPair::generate().unwrap();
        let w = WalletFile::seal(&kp, "correct horse battery", "test").unwrap();
        let address = w.address.clone();
        WalletServer::new(
            KeySource::Wallet(w),
            address,
            "test".into(),
            "http://127.0.0.1:1".into(),
            "https://q-lock-ecosystem.com/explorer/".into(),
            "127.0.0.1".into(),
            7369,
        )
    }

    fn request(method: &str, path: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                .collect(),
            body: Zeroizing::new(Vec::new()),
        }
    }

    #[test]
    fn the_page_is_served_to_its_own_host() {
        let s = server();
        let r = s.route(&request("GET", "/", &[("Host", "127.0.0.1:7369")]));
        assert_eq!(r.0, 200);
        assert!(String::from_utf8_lossy(&r.2).contains("NEV369"));
    }

    #[test]
    fn a_wildcard_bind_prints_links_a_browser_can_open() {
        let mut s = server();
        assert!(s.url().starts_with("http://127.0.0.1:7369/#t="));
        assert!(s.chromeos_url().is_none());
        s.bind = "0.0.0.0".into();
        assert!(s.url().starts_with("http://127.0.0.1:7369/#t="));
        assert!(s
            .chromeos_url()
            .unwrap()
            .starts_with("http://penguin.linux.test:7369/#t="));
    }

    #[test]
    fn a_foreign_host_is_refused() {
        // DNS rebinding: attacker.example resolving to 127.0.0.1.
        let s = server();
        let r = s.route(&request("GET", "/", &[("Host", "attacker.example:7369")]));
        assert_eq!(r.0, 403);
    }

    #[test]
    fn the_api_needs_the_token() {
        let s = server();
        let no_token = s.route(&request("GET", "/api/state", &[("Host", "127.0.0.1:7369")]));
        assert_eq!(no_token.0, 401);
        let wrong = s.route(&request(
            "GET",
            "/api/state",
            &[("Host", "127.0.0.1:7369"), ("X-Wallet-Token", "00")],
        ));
        assert_eq!(wrong.0, 401);
        let token = s.token.clone();
        let right = s.route(&request(
            "GET",
            "/api/state",
            &[
                ("Host", "127.0.0.1:7369"),
                ("X-Wallet-Token", token.as_str()),
            ],
        ));
        assert_eq!(right.0, 200);
        assert!(String::from_utf8_lossy(&right.2).contains(&s.address));
    }

    #[test]
    fn another_site_cannot_drive_the_api() {
        let s = server();
        let token = s.token.clone();
        let r = s.route(&request(
            "POST",
            "/api/send",
            &[
                ("Host", "127.0.0.1:7369"),
                ("Origin", "https://evil.example"),
                ("X-Wallet-Token", token.as_str()),
            ],
        ));
        assert_eq!(r.0, 403);
    }

    #[test]
    fn the_token_is_long_and_not_in_the_page() {
        let s = server();
        assert_eq!(s.token.len(), 64);
        assert!(!UI.contains(&s.token));
        assert!(s.url().contains(&format!("#t={}", s.token)));
    }

    #[test]
    fn constant_time_compare_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
