//! cell.host: runs guests' T0 cells. Each call is one jailed `ce-t0` process (no key, no network,
//! nothing mapped in but the precompiled cell), so a cell that misbehaves ends only its own call.
//! This host is the spending node: it counts every call against the guest grant's quota
//! (`max_credits`) and refuses after the grant's `not_after`, when the cell also expires.
//!
//! Ops (POST /<Op>, JSON; `grant` = {chain, ts, sig}, signed by the guest key):
//!   Deploy{artifact_sha256, descriptor, grant} -> {instance, not_after, quota, imports}
//!   Call{instance, op, grant}                  -> {report, state, calls_used, calls_left}
//!   Usage{instance}                            -> {status, calls_used, quota, not_after, state, last}
//!   Stop{instance, grant}                      -> {status}
//!
//!   cell-host serve [addr]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Result};
use base64::Engine as _;
use play_http::{json, now, Req, Resp, Value};
use sha2::{Digest, Sha256};

const MAX_INSTANCES: usize = 200;

struct Instance {
    owner: String, // cap_id of the guest leaf
    artifact: String,
    descriptor: Value,
    cwasm: PathBuf,
    not_after: u64,
    quota: u64,
    used: u64,
    state: i64,
    status: &'static str, // live | expired | stopped | replaced
    last: Value,
}

struct Svc {
    data: PathBuf,
    t0: PathBuf,
    build_url: String,
    grant_url: String,
    root: Mutex<Option<[u8; 32]>>,
    compile_lock: Mutex<()>,
    instances: Mutex<HashMap<String, Instance>>,
}

fn root_key(s: &Svc) -> Result<[u8; 32], Resp> {
    if let Some(r) = *s.root.lock().unwrap() {
        return Ok(r);
    }
    let (_, v) = play_http::call(&s.grant_url, "Root", &json!({})).map_err(|e| Resp::error(503, &format!("play.grant unreachable: {e}")))?;
    let r: [u8; 32] = v["root"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok()).ok_or_else(|| Resp::error(503, "play.grant gave no root"))?;
    *s.root.lock().unwrap() = Some(r);
    Ok(r)
}

fn rand_id() -> String {
    let mut r = [0u8; 6];
    getrandom::getrandom(&mut r).expect("os random");
    format!("c-{}", hex::encode(r))
}

fn deploy(s: &Svc, body: &Value) -> Result<Resp, Resp> {
    let root = root_key(s)?;
    let art = body["artifact_sha256"].as_str().unwrap_or("").to_ascii_lowercase();
    let leaf = play_cap::authorize_request(&body["grant"], &root, now(), "play:deploy", &art, "Deploy").map_err(|e| Resp::error(401, &e))?;
    let desc = body["descriptor"].clone();
    if desc["artifact"]["sha256"].as_str() != Some(art.as_str()) || desc["tier"] != "T0" {
        return Err(Resp::error(400, "descriptor does not name this artifact on tier T0"));
    }
    // Fetch by hash and check the hash: the artifact store cannot hand us other bytes.
    let (code, v) = play_http::call(&s.build_url, "Get", &json!({ "sha256": art })).map_err(|e| Resp::error(503, &e.to_string()))?;
    if code != 200 {
        return Err(Resp::error(404, "artifact not found by hash"));
    }
    let wasm = base64::engine::general_purpose::STANDARD.decode(v["bytes_b64"].as_str().unwrap_or("")).map_err(|_| Resp::error(502, "bad artifact bytes"))?;
    if hex::encode(Sha256::digest(&wasm)) != art {
        return Err(Resp::error(502, "artifact bytes do not match their hash"));
    }
    let dir = s.data.join("host/cells");
    std::fs::create_dir_all(&dir).map_err(|e| Resp::error(500, &e.to_string()))?;
    let (wasm_p, cwasm_p) = (dir.join(format!("{art}.wasm")), dir.join(format!("{art}.cwasm")));
    let mut imports: Value =
        std::fs::read(dir.join(format!("{art}.imports.json"))).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!([]));
    if !cwasm_p.exists() {
        std::fs::write(&wasm_p, &wasm).map_err(|e| Resp::error(500, &e.to_string()))?;
        // Precompile inside the jail too: the compiler sees untrusted bytes. One at a time.
        let _one = s.compile_lock.lock().unwrap();
        let staging = s.data.join("host/staging");
        std::fs::create_dir_all(&staging).map_err(|e| Resp::error(500, &e.to_string()))?;
        std::fs::copy(&wasm_p, staging.join("cell.wasm")).map_err(|e| Resp::error(500, &e.to_string()))?;
        let out = ce_t0::jail(&[(&s.t0, "/t0")], Some(&staging), 60, &["/t0", "compile", "/build/cell.wasm", "/build/cell.cwasm"])
            .output()
            .map_err(|e| Resp::error(500, &format!("jail: {e}")))?;
        let report: Value = serde_json::from_slice(&out.stdout).unwrap_or(json!({"kind": "error", "error": "no report"}));
        if report["kind"] != "compiled" {
            return Err(Resp::error(422, &format!("T0 refused the artifact: {}", report["error"].as_str().unwrap_or("unknown"))));
        }
        imports = report["imports"].clone();
        std::fs::write(dir.join(format!("{art}.imports.json")), imports.to_string()).map_err(|e| Resp::error(500, &e.to_string()))?;
        std::fs::rename(staging.join("cell.cwasm"), &cwasm_p).map_err(|e| Resp::error(500, &e.to_string()))?;
    }
    let owner = hex::encode(play_cap::cap_id(&leaf));
    let quota = leaf.caveats.max_credits.unwrap_or(0);
    let not_after = leaf.caveats.not_after;
    let mut m = s.instances.lock().unwrap();
    if m.values().filter(|i| i.status == "live").count() >= MAX_INSTANCES {
        return Err(Resp::error(503, "the playground is full; try again in a few minutes"));
    }
    // One live cell per guest: a new deploy replaces the old one and keeps the quota already spent.
    let mut used = 0;
    for i in m.values_mut().filter(|i| i.owner == owner && i.status == "live") {
        i.status = "replaced";
        used = used.max(i.used);
    }
    let id = rand_id();
    m.insert(
        id.clone(),
        Instance { owner, artifact: art.clone(), descriptor: desc, cwasm: cwasm_p, not_after, quota, used, state: 0, status: "live", last: Value::Null },
    );
    Ok(Resp::ok(json!({ "instance": id, "artifact_sha256": art, "not_after": not_after, "quota": quota, "calls_used": used, "imports": imports })))
}

fn call(s: &Svc, body: &Value) -> Result<Resp, Resp> {
    let root = root_key(s)?;
    let id = body["instance"].as_str().unwrap_or("").to_string();
    let op = body["op"].as_str().unwrap_or("").to_string();
    let leaf = play_cap::authorize_request(&body["grant"], &root, now(), "play:call", &id, &op).map_err(|e| Resp::error(401, &format!("refused: {e}")))?;
    let owner = hex::encode(play_cap::cap_id(&leaf));
    let (cwasm, state) = {
        let mut m = s.instances.lock().unwrap();
        let i = m.get_mut(&id).ok_or_else(|| Resp::error(404, "no such cell"))?;
        if i.owner != owner {
            return Err(Resp::error(403, "refused: this grant does not own that cell"));
        }
        if now() > i.not_after || i.status == "expired" {
            i.status = "expired";
            return Err(Resp::error(410, &format!("refused: the cell expired at {}", i.not_after)));
        }
        if i.status != "live" {
            return Err(Resp::error(410, &format!("refused: the cell is {}", i.status)));
        }
        if i.used >= i.quota {
            return Err(Resp::error(429, &format!("refused: quota spent ({} of {} calls)", i.used, i.quota)));
        }
        if !i.descriptor["ops"].as_array().is_some_and(|a| a.iter().any(|o| o == op.as_str())) {
            return Err(Resp::error(400, &format!("the cell has no op {op}")));
        }
        i.used += 1; // counted before running: a call that traps still spends quota
        (i.cwasm.clone(), i.state)
    };
    let report = ce_t0::jailed_call(&s.t0, &cwasm, &op, state, ce_t0::Limits::default()).map_err(|e| Resp::error(500, &format!("{e:#}")))?;
    let mut m = s.instances.lock().unwrap();
    let i = m.get_mut(&id).ok_or_else(|| Resp::error(404, "no such cell"))?;
    if report["kind"] == "ok" {
        i.state = report["state"].as_i64().unwrap_or(i.state);
    }
    i.last = report.clone();
    Ok(Resp::ok(json!({ "report": report, "state": i.state, "calls_used": i.used, "calls_left": i.quota.saturating_sub(i.used), "quota": i.quota, "not_after": i.not_after })))
}

fn handle(s: &Svc, req: Req) -> Resp {
    let body = match req.json() {
        Ok(v) => v,
        Err(r) => return r,
    };
    let r = match req.op() {
        "Deploy" => deploy(s, &body),
        "Call" => call(s, &body),
        "Usage" => {
            let m = s.instances.lock().unwrap();
            match m.get(body["instance"].as_str().unwrap_or("")) {
                Some(i) => Ok(Resp::ok(json!({
                    "status": if i.status == "live" && now() > i.not_after { "expired" } else { i.status },
                    "artifact_sha256": i.artifact, "calls_used": i.used, "quota": i.quota,
                    "not_after": i.not_after, "now": now(), "state": i.state, "last": i.last,
                }))),
                None => Err(Resp::error(404, "no such cell")),
            }
        }
        "Stop" => (|| {
            let root = root_key(s)?;
            let id = body["instance"].as_str().unwrap_or("");
            let leaf = play_cap::authorize_request(&body["grant"], &root, now(), "play:deploy", id, "Stop").map_err(|e| Resp::error(401, &e))?;
            let mut m = s.instances.lock().unwrap();
            let i = m.get_mut(id).ok_or_else(|| Resp::error(404, "no such cell"))?;
            if i.owner != hex::encode(play_cap::cap_id(&leaf)) {
                return Err(Resp::error(403, "this grant does not own that cell"));
            }
            i.status = "stopped";
            i.state = 0;
            Ok(Resp::ok(json!({ "status": "stopped" })))
        })(),
        op => Err(Resp::error(404, &format!("cell.host has no op {op}"))),
    };
    r.unwrap_or_else(|e| e)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("serve") {
        bail!("usage: cell-host serve [addr]");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let data = std::env::var("PLAY_DATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(&home).join(".local/share/demo-playground"));
    let t0 = std::env::var("PLAY_T0").map(PathBuf::from).unwrap_or_else(|_| {
        std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("ce-t0"))).unwrap_or_else(|| "ce-t0".into())
    });
    let svc = Arc::new(Svc {
        data,
        t0,
        build_url: std::env::var("PLAY_BUILD_URL").unwrap_or_else(|_| "http://127.0.0.1:7862".into()),
        grant_url: std::env::var("PLAY_GRANT_URL").unwrap_or_else(|_| "http://127.0.0.1:7861".into()),
        root: Mutex::new(None),
        compile_lock: Mutex::new(()),
        instances: Mutex::new(HashMap::new()),
    });
    // Expiry: a cell ends at its grant's not_after; its state goes with it.
    {
        let svc = svc.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let t = now();
            for i in svc.instances.lock().unwrap().values_mut() {
                if i.status == "live" && t > i.not_after {
                    i.status = "expired";
                    i.state = 0;
                }
            }
        });
    }
    let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:7863".into());
    play_http::serve(&addr, 8, Arc::new(move |r| handle(&svc, r)))
}
