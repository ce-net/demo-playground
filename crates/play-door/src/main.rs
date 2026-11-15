//! play-door: the playground's public HTTP edge. Serves the page and routes each /api call to the
//! one cell that answers it; it holds no key and decides nothing itself, apart from a per-address
//! request budget.
//!
//!   POST /api/grant/{challenge,guest,decode}  -> play.grant@1
//!   POST /api/build, GET /api/templates       -> build.wasm@1
//!   GET  /api/blob/<sha256>                   -> build.wasm@1 Get (artifact or source, raw)
//!   POST /api/{deploy,call,usage,stop}        -> cell.host
//!   POST /api/client                          -> client.gen@1
//!
//!   play-door serve [addr] [web dir]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use base64::Engine as _;
use play_http::{json, now, Req, Resp, Value};

const REQS_PER_MIN: usize = 240;

struct Door {
    web: PathBuf,
    grant: String,
    build: String,
    host: String,
    gen: String,
    public_url: String,
    hits: Mutex<HashMap<String, Vec<u64>>>,
}

fn route<'a>(d: &'a Door, path: &str) -> Option<(&'a str, &'static str)> {
    Some(match path {
        "/api/grant/challenge" => (&d.grant, "Challenge"),
        "/api/grant/guest" => (&d.grant, "Guest"),
        "/api/grant/decode" => (&d.grant, "Decode"),
        "/api/grant/root" => (&d.grant, "Root"),
        "/api/build" => (&d.build, "Build"),
        "/api/templates" => (&d.build, "Templates"),
        "/api/deploy" => (&d.host, "Deploy"),
        "/api/call" => (&d.host, "Call"),
        "/api/usage" => (&d.host, "Usage"),
        "/api/stop" => (&d.host, "Stop"),
        "/api/client" => (&d.gen, "Gen"),
        _ => return None,
    })
}

fn static_file(web: &Path, path: &str) -> Resp {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.split('/').any(|p| p == ".." || p.starts_with('.')) {
        return Resp::error(404, "not found");
    }
    let p = web.join(rel);
    let ct = match p.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    match std::fs::read(&p) {
        Ok(b) => Resp::bytes(200, ct, b).header("Cache-Control", "no-cache"),
        Err(_) => Resp::error(404, "not found"),
    }
}

fn handle(d: &Door, req: Req) -> Resp {
    {
        let mut h = d.hits.lock().unwrap();
        let t = now();
        if h.len() > 50_000 {
            h.retain(|_, v| v.last().is_some_and(|x| t - *x < 60));
        }
        let v = h.entry(req.client.clone()).or_default();
        v.retain(|x| t - *x < 60);
        if v.len() >= REQS_PER_MIN {
            return Resp::error(429, "too many requests from this address; wait a minute");
        }
        v.push(t);
    }
    let resp = if let Some(sha) = req.path.strip_prefix("/api/blob/") {
        match play_http::call(&d.build, "Get", &json!({ "sha256": sha })) {
            Ok((200, v)) => {
                let b = base64::engine::general_purpose::STANDARD.decode(v["bytes_b64"].as_str().unwrap_or("")).unwrap_or_default();
                let ct = if b.starts_with(b"\0asm") { "application/wasm" } else { "text/plain; charset=utf-8" };
                Resp::bytes(200, ct, b).header("Content-Disposition", &format!("inline; filename=\"{sha}\""))
            }
            Ok((code, v)) => Resp::json(code, &v),
            Err(e) => Resp::error(503, &e.to_string()),
        }
    } else if let Some((base, op)) = route(d, &req.path) {
        let mut body: Value = if req.body.is_empty() { json!({}) } else { req.json().unwrap_or(json!({})) };
        if op == "Gen" {
            body["door"] = d.public_url.clone().into();
        }
        match play_http::call_as(base, op, &body, Some(&req.client)) {
            Ok((code, v)) => Resp::json(code, &v),
            Err(e) => Resp::error(503, &format!("cell unreachable: {e}")),
        }
    } else if req.path == "/api/config" {
        Resp::ok(json!({ "door": d.public_url }))
    } else if req.method == "GET" {
        static_file(&d.web, &req.path)
    } else {
        Resp::error(404, "not found")
    };
    resp.header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header("Content-Security-Policy", "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://ce-net.com https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("serve") {
        bail!("usage: play-door serve [addr] [web dir]");
    }
    let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:7860".into());
    let web = args.get(2).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("web"));
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let door = Arc::new(Door {
        web,
        grant: env("PLAY_GRANT_URL", "http://127.0.0.1:7861"),
        build: env("PLAY_BUILD_URL", "http://127.0.0.1:7862"),
        host: env("PLAY_HOST_URL", "http://127.0.0.1:7863"),
        gen: env("PLAY_GEN_URL", "http://127.0.0.1:7864"),
        public_url: env("PLAY_PUBLIC_URL", &format!("http://{addr}")),
        hits: Mutex::new(HashMap::new()),
    });
    play_http::serve(&addr, 16, Arc::new(move |r| handle(&door, r)))
}
