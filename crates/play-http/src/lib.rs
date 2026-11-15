//! The wire every playground cell speaks: `POST /<Op>` with a JSON body, a JSON answer and an HTTP
//! status (200 ok, 4xx refused with `{"error": ...}`). Cells bind to loopback; only the door is
//! exposed. Kept tiny on purpose so any language can call a cell with its standard library.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

pub use serde_json::{json, Value};

pub const MAX_BODY: usize = 4 * 1024 * 1024;

pub struct Req {
    pub method: String,
    /// Path without the query string, e.g. `/Build`.
    pub path: String,
    pub query: String,
    pub body: Vec<u8>,
    /// The client address: `X-Forwarded-For` from a trusted local edge, else the socket peer.
    pub client: String,
}

impl Req {
    pub fn json(&self) -> Result<Value, Resp> {
        serde_json::from_slice(&self.body).map_err(|e| Resp::error(400, &format!("body is not JSON: {e}")))
    }
    /// The op name for `POST /<Op>`.
    pub fn op(&self) -> &str {
        self.path.trim_start_matches('/')
    }
}

pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn json(status: u16, v: &Value) -> Resp {
        Resp { status, content_type: "application/json".into(), body: serde_json::to_vec(v).unwrap(), headers: vec![] }
    }
    pub fn ok(v: Value) -> Resp {
        Resp::json(200, &v)
    }
    pub fn error(status: u16, msg: &str) -> Resp {
        Resp::json(status, &json!({ "error": msg }))
    }
    pub fn bytes(status: u16, content_type: &str, body: Vec<u8>) -> Resp {
        Resp { status, content_type: content_type.into(), body, headers: vec![] }
    }
    pub fn header(mut self, k: &str, v: &str) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

pub type Handler = Arc<dyn Fn(Req) -> Resp + Send + Sync>;

/// Serve `handler` on `addr` with `threads` workers. Blocks forever.
pub fn serve(addr: &str, threads: usize, handler: Handler) -> anyhow::Result<()> {
    let server = Arc::new(tiny_http::Server::http(addr).map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?);
    eprintln!("listening on http://{addr}");
    let mut joins = vec![];
    for _ in 0..threads.max(1) {
        let server = server.clone();
        let handler = handler.clone();
        joins.push(std::thread::spawn(move || loop {
            let Ok(mut rq) = server.recv() else { continue };
            let resp = match read(&mut rq) {
                Ok(req) => handler(req),
                Err(r) => r,
            };
            let mut out = tiny_http::Response::from_data(resp.body).with_status_code(resp.status);
            let mut hs = vec![("Content-Type".to_string(), resp.content_type)];
            hs.extend(resp.headers);
            for (k, v) in hs {
                if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
                    out.add_header(h);
                }
            }
            let _ = rq.respond(out);
        }));
    }
    for j in joins {
        let _ = j.join();
    }
    Ok(())
}

fn read(rq: &mut tiny_http::Request) -> Result<Req, Resp> {
    let peer = rq.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let loopback = peer == "127.0.0.1" || peer == "::1";
    let fwd = rq
        .headers()
        .iter()
        .find(|h| h.field.equiv("X-Forwarded-For") || h.field.equiv("CF-Connecting-IP"))
        .map(|h| h.value.as_str().split(',').next().unwrap_or("").trim().to_string());
    // Only a local edge (the door, a tunnel) may name the client; anyone else is who they are.
    let client = match (loopback, fwd) {
        (true, Some(f)) if !f.is_empty() => f,
        _ => peer,
    };
    let url = rq.url().to_string();
    let (path, query) = match url.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (url, String::new()),
    };
    let mut body = Vec::new();
    rq.as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| Resp::error(400, "could not read body"))?;
    if body.len() > MAX_BODY {
        return Err(Resp::error(413, "body is larger than 4 MB"));
    }
    Ok(Req { method: rq.method().to_string(), path, query, body, client })
}

/// Call `op` on the cell at `base` (e.g. `http://127.0.0.1:7862`). Returns the status and JSON answer.
pub fn call(base: &str, op: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
    call_as(base, op, body, None)
}

/// As [`call`], naming the end client so the callee can rate-limit per client.
pub fn call_as(base: &str, op: &str, body: &Value, client: Option<&str>) -> anyhow::Result<(u16, Value)> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(120)).build();
    let mut rq = agent.post(&format!("{base}/{op}"));
    if let Some(c) = client {
        rq = rq.set("X-Forwarded-For", c);
    }
    match rq.send_json(body.clone()) {
        Ok(r) => Ok((r.status(), r.into_json()?)),
        Err(ureq::Error::Status(code, r)) => Ok((code, r.into_json().unwrap_or(json!({"error": "no body"})))),
        Err(e) => Err(anyhow::anyhow!("{base}/{op}: {e}")),
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}
