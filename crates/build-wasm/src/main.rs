//! build.wasm@1: turn a Rust or JavaScript cell source into a T0 WebAssembly artifact, inside a
//! jail with no network, and say exactly how anyone can rebuild the same bytes.
//!
//! Ops (POST /<Op>, JSON):
//!   Build{lang, src, grant}  -> {artifact_sha256, descriptor, log}
//!   Get{sha256}              -> {bytes_b64}            (an artifact or a source, by hash)
//!   Templates{}              -> [{lang, name, src}]
//!
//! CLI:
//!   build-wasm serve [addr]
//!   build-wasm rebuild <descriptor.json> <source file>   rebuild locally and compare the hash

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use play_http::{json, Req, Resp, Value};
use sha2::{Digest, Sha256};

const MAX_SRC: usize = 16 * 1024;
const MAX_ARTIFACT: u64 = 4 * 1024 * 1024;
const BUILD_TIMEOUT: Duration = Duration::from_secs(90);
const BUILDS_PER_GRANT: u32 = 30;

const SDK_RS: &str = include_str!("../../../sdk/t0.rs");
const SDK_JS: &str = include_str!("../../../sdk/t0.js");
const TEMPLATES: &[(&str, &str, &str)] = &[
    ("rust", "counter", include_str!("../../../templates/rust/counter.rs")),
    ("rust", "net-probe", include_str!("../../../templates/rust/net-probe.rs")),
    ("js", "counter", include_str!("../../../templates/js/counter.js")),
    ("js", "spin", include_str!("../../../templates/js/spin.js")),
];

const RUST_ARGS: &[&str] = &[
    "--edition", "2021", "--target", "wasm32-wasip1", "-C", "opt-level=s", "-C", "codegen-units=1",
    "-C", "debuginfo=0", "-C", "strip=symbols", "--crate-name", "cell", "main.rs", "-o", "cell.wasm",
];
const JAVY_ARGS: &[&str] = &[
    "build", "-C", "deterministic=y", "-C", "source=omitted", "-J", "javy-stream-io=y", "-J", "text-encoding=y",
    "-o", "cell.wasm", "bundle.js",
];

struct Cfg {
    data: PathBuf,
    sysroot: PathBuf,
    rustc_version: String,
    javy: PathBuf,
    javy_version: String,
    t0: PathBuf,
    grant_url: String,
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn cfg() -> Result<Cfg> {
    let home = std::env::var("HOME").unwrap_or_default();
    let data = std::env::var("PLAY_DATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(&home).join(".local/share/demo-playground"));
    let rustc = std::env::var("PLAY_RUSTC").unwrap_or_else(|_| "rustc".into());
    let sysroot = PathBuf::from(cmd_out(&rustc, &["--print", "sysroot"])?);
    let rustc_version = cmd_out(&sysroot.join("bin/rustc").to_string_lossy(), &["--version"])?;
    if !sysroot.join("lib/rustlib/wasm32-wasip1").exists() {
        bail!("the wasm32-wasip1 target is missing: rustup target add wasm32-wasip1");
    }
    let javy = std::env::var("PLAY_JAVY").map(PathBuf::from).unwrap_or_else(|_| data.join("toolchain/javy"));
    let javy_version = cmd_out(&javy.to_string_lossy(), &["--version"]).unwrap_or_else(|_| "javy missing".into());
    let t0 = std::env::var("PLAY_T0").map(PathBuf::from).unwrap_or_else(|_| sibling("ce-t0"));
    let grant_url = std::env::var("PLAY_GRANT_URL").unwrap_or_else(|_| "http://127.0.0.1:7861".into());
    Ok(Cfg { data, sysroot, rustc_version, javy, javy_version, t0, grant_url })
}

fn sibling(name: &str) -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join(name))).unwrap_or_else(|| PathBuf::from(name))
}

fn cmd_out(cmd: &str, args: &[&str]) -> Result<String> {
    let o = Command::new(cmd).args(args).output().with_context(|| format!("run {cmd}"))?;
    if !o.status.success() {
        bail!("{cmd} {args:?} failed");
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Wait for a child with a wall-clock limit; returns (success, combined log).
fn run_limited(mut c: Command, limit: Duration) -> Result<(bool, String)> {
    let mut child = c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("start the build jail (needs bwrap and prlimit)")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let mut log = String::new();
            if let Some(mut s) = child.stdout.take() {
                let _ = s.read_to_string(&mut log);
            }
            if let Some(mut s) = child.stderr.take() {
                let _ = s.read_to_string(&mut log);
            }
            log.truncate(8000);
            return Ok((status.success(), log));
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return Ok((false, format!("build stopped: wall-clock limit of {} s", limit.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Built {
    wasm: Vec<u8>,
    log: String,
    descriptor: Value,
}

/// The source as the build sees it: Rust gets t0.rs beside main.rs; JS gets the SDK prepended.
fn build(cfg: &Cfg, lang: &str, src: &str) -> Result<Built> {
    if src.len() > MAX_SRC {
        bail!("source is larger than 16 KB");
    }
    let dir = workdir(&cfg.data, if lang == "rust" { "rust" } else { "js" })?;
    let (argv, toolchain, sdk_file, sdk_src): (Vec<&str>, Value, &str, &str) = match lang {
        "rust" => {
            std::fs::write(dir.join("main.rs"), src)?;
            std::fs::write(dir.join("t0.rs"), SDK_RS)?;
            let mut a = vec!["/toolchain/bin/rustc"];
            a.extend(RUST_ARGS);
            (a, json!({ "name": cfg.rustc_version, "target": "wasm32-wasip1" }), "t0.rs", SDK_RS)
        }
        "js" => {
            std::fs::write(dir.join("main.js"), src)?;
            std::fs::write(dir.join("t0.js"), SDK_JS)?;
            std::fs::write(dir.join("bundle.js"), format!("{SDK_JS}\n{src}"))?;
            let mut a = vec!["/toolchain/bin/javy"];
            a.extend(JAVY_ARGS);
            (a, json!({ "name": cfg.javy_version, "release": "https://github.com/bytecodealliance/javy/releases/tag/v9.1.0" }), "t0.js", SDK_JS)
        }
        _ => bail!("lang must be rust or js"),
    };
    let toolchain_dir = match lang {
        "rust" => cfg.sysroot.clone(),
        _ => {
            // javy is one file; give the jail a directory with only it inside.
            let d = cfg.data.join("toolchain/javy-root/bin");
            std::fs::create_dir_all(&d)?;
            let target = d.join("javy");
            if !target.exists() {
                std::fs::copy(&cfg.javy, &target)?;
            }
            d.parent().unwrap().to_path_buf()
        }
    };
    let c = ce_t0::jail(&[(&toolchain_dir, "/toolchain")], Some(&dir), 120, &argv);
    let (ok, log) = run_limited(c, BUILD_TIMEOUT)?;
    let out = dir.join("cell.wasm");
    if !ok || std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0) == 0 {
        bail!("build failed:\n{log}");
    }
    if std::fs::metadata(&out)?.len() > MAX_ARTIFACT {
        bail!("artifact is larger than 4 MB");
    }
    let wasm = std::fs::read(&out)?;
    // Ask the cell what it answers, under T0 like any call.
    let report = ce_t0::jailed_call(&cfg.t0, &out, "__describe", 0, ce_t0::Limits::default())?;
    let ops: Vec<String> = match report["kind"].as_str() {
        Some("ops") => serde_json::from_value(report["ops"].clone())?,
        _ => bail!("the cell built but did not describe its ops under T0: {report}"),
    };
    let command = match lang {
        "rust" => format!("rustc {}", RUST_ARGS.join(" ")),
        _ => format!("cat t0.js main.js > bundle.js && javy {}", JAVY_ARGS.join(" ")),
    };
    let descriptor = json!({
        "format": "play-descriptor-v0",
        "tier": "T0",
        "lang": lang,
        "ops": ops,
        "state": "i64",
        "artifact": { "sha256": sha(&wasm), "bytes": wasm.len() },
        "source": { "file": if lang == "rust" { "main.rs" } else { "main.js" }, "sha256": sha(src.as_bytes()), "bytes": src.len() },
        "sdk": { "file": sdk_file, "sha256": sha(sdk_src.as_bytes()) },
        "toolchain": toolchain,
        "command": command,
        "rebuild": "build-wasm rebuild descriptor.json <source file>  (github.com/ce-net/demo-playground)",
    });
    Ok(Built { wasm, log, descriptor })
}

/// One work directory per language, reused (builds run one at a time). The previous artifact is
/// truncated first so a failed build can never hand back an old one.
fn workdir(data: &Path, lang: &str) -> Result<PathBuf> {
    let d = data.join("builds").join(lang);
    std::fs::create_dir_all(&d)?;
    std::fs::write(d.join("cell.wasm"), b"")?;
    Ok(d)
}

fn blob_path(data: &Path, h: &str) -> Result<PathBuf> {
    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("sha256 must be 64 hex characters");
    }
    Ok(data.join("blobs").join(h.to_ascii_lowercase()))
}

fn put_blob(data: &Path, bytes: &[u8]) -> Result<String> {
    let h = sha(bytes);
    let p = blob_path(data, &h)?;
    if !p.exists() {
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, &p)?;
    }
    Ok(h)
}

struct Svc {
    cfg: Cfg,
    lock: Mutex<()>,
    builds: Mutex<HashMap<String, u32>>,
    root: Mutex<Option<[u8; 32]>>,
}

fn root_key(s: &Svc) -> Result<[u8; 32], Resp> {
    if let Some(r) = *s.root.lock().unwrap() {
        return Ok(r);
    }
    let (_, v) = play_http::call(&s.cfg.grant_url, "Root", &json!({})).map_err(|e| Resp::error(503, &format!("play.grant unreachable: {e}")))?;
    let r: [u8; 32] = v["root"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok()).ok_or_else(|| Resp::error(503, "play.grant gave no root"))?;
    *s.root.lock().unwrap() = Some(r);
    Ok(r)
}

fn handle(s: &Svc, req: Req) -> Resp {
    let body = match req.json() {
        Ok(v) => v,
        Err(r) => return r,
    };
    match req.op() {
        "Templates" => Resp::ok(json!(TEMPLATES.iter().map(|(l, n, src)| json!({"lang": l, "name": n, "src": src})).collect::<Vec<_>>())),
        "Get" => {
            let p = match blob_path(&s.cfg.data, body["sha256"].as_str().unwrap_or("")) {
                Ok(p) => p,
                Err(e) => return Resp::error(400, &e.to_string()),
            };
            match std::fs::read(p) {
                Ok(b) => Resp::ok(json!({ "bytes_b64": base64::engine::general_purpose::STANDARD.encode(b) })),
                Err(_) => Resp::error(404, "no blob with that hash"),
            }
        }
        "Build" => {
            let root = match root_key(s) {
                Ok(r) => r,
                Err(r) => return r,
            };
            let leaf = match play_cap::authorize_request(&body["grant"], &root, play_http::now(), "play:build", "build", "Build") {
                Ok(l) => l,
                Err(e) => return Resp::error(401, &e),
            };
            let id = hex::encode(play_cap::cap_id(&leaf));
            {
                let mut b = s.builds.lock().unwrap();
                let n = b.entry(id).or_insert(0);
                if *n >= BUILDS_PER_GRANT {
                    return Resp::error(429, &format!("build quota spent: {BUILDS_PER_GRANT} builds per guest grant"));
                }
                *n += 1;
            }
            let (lang, src) = (body["lang"].as_str().unwrap_or(""), body["src"].as_str().unwrap_or(""));
            let _one_at_a_time = s.lock.lock().unwrap();
            let started = Instant::now();
            match build(&s.cfg, lang, src) {
                Ok(b) => {
                    let h = match put_blob(&s.cfg.data, &b.wasm).and_then(|h| put_blob(&s.cfg.data, src.as_bytes()).map(|_| h)) {
                        Ok(h) => h,
                        Err(e) => return Resp::error(500, &e.to_string()),
                    };
                    let dtext = serde_json::to_vec_pretty(&b.descriptor).unwrap();
                    let dh = match put_blob(&s.cfg.data, &dtext) {
                        Ok(h) => h,
                        Err(e) => return Resp::error(500, &e.to_string()),
                    };
                    Resp::ok(json!({ "artifact_sha256": h, "descriptor_sha256": dh, "descriptor": b.descriptor, "log": b.log, "ms": started.elapsed().as_millis() as u64 }))
                }
                Err(e) => Resp::error(422, &format!("{e:#}")),
            }
        }
        op => Resp::error(404, &format!("build.wasm@1 has no op {op}")),
    }
}

fn rebuild(desc_path: &str, src_path: &str) -> Result<()> {
    let cfg = cfg()?;
    let desc: Value = serde_json::from_slice(&std::fs::read(desc_path)?)?;
    let src = std::fs::read_to_string(src_path)?;
    let lang = desc["lang"].as_str().unwrap_or("");
    let want_tc = desc["toolchain"]["name"].as_str().unwrap_or("");
    let have_tc = if lang == "rust" { &cfg.rustc_version } else { &cfg.javy_version };
    println!("toolchain  wanted {want_tc}\n           here   {have_tc}");
    if desc["source"]["sha256"].as_str() != Some(&sha(src.as_bytes())) {
        bail!("this source is not the one the descriptor names (sha256 differs)");
    }
    std::fs::create_dir_all(&cfg.data)?;
    let b = build(&cfg, lang, &src)?;
    let (want, got) = (desc["artifact"]["sha256"].as_str().unwrap_or(""), sha(&b.wasm));
    println!("artifact   wanted {want}\n           built  {got}");
    if want != got {
        bail!("MISMATCH");
    }
    println!("MATCH: the same source and toolchain give the same artifact");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("rebuild") if args.len() == 3 => rebuild(&args[1], &args[2]),
        Some("serve") => {
            let cfg = cfg()?;
            std::fs::create_dir_all(cfg.data.join("blobs"))?;
            eprintln!("build.wasm@1: {} | {} | t0 {}", cfg.rustc_version, cfg.javy_version, cfg.t0.display());
            let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:7862".into());
            let svc = Arc::new(Svc { cfg, lock: Mutex::new(()), builds: Mutex::new(HashMap::new()), root: Mutex::new(None) });
            play_http::serve(&addr, 4, Arc::new(move |r| handle(&svc, r)))
        }
        _ => bail!("usage: build-wasm serve [addr] | build-wasm rebuild <descriptor.json> <source>"),
    }
}
