//! play.grant@1: give a visitor a short guest capability after a captcha.
//!
//! The captcha is proof of work: the visitor's browser finds a nonce so that
//! sha256("<challenge>:<nonce>") starts with `bits` zero bits. It costs a browser about a second
//! and a script farm real CPU per grant, needs no third party and tracks nothing.
//!
//! The grant is a two-link ce-cap-v1 chain: playground root -> this issuer (play:*, 30 days), then
//! issuer -> the visitor's own Ed25519 key (play:build, play:deploy, play:call; a call quota in
//! `max_credits`, `max_mem_mb` 32, `not_after` within 10 minutes). The visitor's secret key never
//! leaves the browser; every later request is signed with it.
//!
//! Ops (POST /<Op>, JSON):
//!   Root{}                                         -> {root}
//!   Challenge{}                                    -> {challenge, bits, not_after}
//!   Guest{challenge, nonce, guest_pub, ttl_s?, calls?} -> {cap_chain, quota, not_after, decoded}
//!   Decode{chain}                                  -> the chain, every field of every link
//!
//!   play-grant serve [addr]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use play_cap::{Capability, Caveats, Resource, SignedCapability};
use play_http::{json, now, Req, Resp};
use sha2::{Digest, Sha256};

const BITS: u32 = 16;
const CHALLENGE_TTL: u64 = 120;
const MAX_TTL: u64 = 600;
const MIN_TTL: u64 = 5;
const MAX_CALLS: u64 = 50;
const GRANTS_PER_IP_PER_HOUR: usize = 20;
const ABILITIES: &[&str] = &["play:build", "play:deploy", "play:call"];

struct Svc {
    root: SigningKey,
    issuer: SigningKey,
    root_link: SignedCapability,
    challenges: Mutex<HashMap<String, u64>>,
    per_ip: Mutex<HashMap<String, Vec<u64>>>,
}

fn load_or_make_key(path: &PathBuf) -> Result<SigningKey> {
    if let Ok(b) = std::fs::read(path) {
        let seed: [u8; 32] = b.try_into().map_err(|_| anyhow::anyhow!("{} is not a 32-byte seed", path.display()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    std::fs::create_dir_all(path.parent().unwrap())?;
    let seed = play_cap::random_seed();
    write_private(path, &seed)?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn write_private(path: &PathBuf, b: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).context("create key file")?;
    f.write_all(b)?;
    Ok(())
}
#[cfg(not(unix))]
fn write_private(path: &PathBuf, b: &[u8]) -> Result<()> {
    std::fs::write(path, b).context("create key file")
}

fn leading_zero_bits(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

fn guest(s: &Svc, body: &play_http::Value, client: &str) -> Result<Resp> {
    let ch = body["challenge"].as_str().unwrap_or("").to_string();
    let nonce = body["nonce"].as_str().unwrap_or("");
    {
        let mut c = s.challenges.lock().unwrap();
        match c.remove(&ch) {
            Some(exp) if exp >= now() => {}
            Some(_) => return Ok(Resp::error(400, "captcha expired; ask for a new challenge")),
            None => return Ok(Resp::error(400, "unknown or already used captcha challenge")),
        }
    }
    if leading_zero_bits(&Sha256::digest(format!("{ch}:{nonce}"))) < BITS {
        return Ok(Resp::error(400, "captcha answer is wrong"));
    }
    {
        let mut m = s.per_ip.lock().unwrap();
        let v = m.entry(client.to_string()).or_default();
        let t = now();
        v.retain(|x| t - *x < 3600);
        if v.len() >= GRANTS_PER_IP_PER_HOUR {
            return Ok(Resp::error(429, &format!("at most {GRANTS_PER_IP_PER_HOUR} guest grants per hour from one address")));
        }
        v.push(t);
    }
    let guest_pub: [u8; 32] = match body["guest_pub"].as_str().and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok()) {
        Some(k) => k,
        None => return Ok(Resp::error(400, "guest_pub must be a 32-byte Ed25519 public key in hex")),
    };
    if ed25519_dalek::VerifyingKey::from_bytes(&guest_pub).is_err() {
        return Ok(Resp::error(400, "guest_pub is not a valid Ed25519 key"));
    }
    let ttl = body["ttl_s"].as_u64().unwrap_or(MAX_TTL).clamp(MIN_TTL, MAX_TTL);
    let calls = body["calls"].as_u64().unwrap_or(MAX_CALLS).clamp(1, MAX_CALLS);
    let not_after = now() + ttl;
    let mut r = [0u8; 8];
    getrandom::getrandom(&mut r).map_err(|e| anyhow::anyhow!("random: {e}"))?;
    let cap = Capability {
        issuer: s.issuer.verifying_key().to_bytes(),
        audience: guest_pub,
        abilities: ABILITIES.iter().map(|a| a.to_string()).collect(),
        resource: Resource::Tag("play".into()),
        caveats: Caveats { not_after, max_credits: Some(calls), max_mem_mb: Some(32), ..Default::default() },
        nonce: u64::from_le_bytes(r),
        parent: Some(play_cap::cap_id(&s.root_link.cap)),
    };
    let chain = vec![s.root_link.clone(), play_cap::sign(&s.issuer, cap)];
    play_cap::verify_chain(&chain, &s.root.verifying_key().to_bytes(), now()).map_err(anyhow::Error::msg)?;
    Ok(Resp::ok(json!({
        "cap_chain": play_cap::chain_hex(&chain),
        "quota": { "calls": calls },
        "not_after": not_after,
        "decoded": play_cap::decode_for_display(&chain),
    })))
}

fn handle(s: &Svc, req: Req) -> Resp {
    let body = match req.json() {
        Ok(v) => v,
        Err(r) => return r,
    };
    match req.op() {
        "Root" => Resp::ok(json!({ "root": hex::encode(s.root.verifying_key().to_bytes()) })),
        "Challenge" => {
            let mut r = [0u8; 16];
            if getrandom::getrandom(&mut r).is_err() {
                return Resp::error(500, "no randomness");
            }
            let ch = hex::encode(r);
            let exp = now() + CHALLENGE_TTL;
            let mut c = s.challenges.lock().unwrap();
            let t = now();
            c.retain(|_, e| *e >= t);
            if c.len() > 10_000 {
                return Resp::error(503, "too many open captchas; try again in a minute");
            }
            c.insert(ch.clone(), exp);
            Resp::ok(json!({ "challenge": ch, "bits": BITS, "not_after": exp, "rule": "sha256(challenge + ':' + nonce) starts with `bits` zero bits" }))
        }
        "Guest" => guest(s, &body, &req.client).unwrap_or_else(|e| Resp::error(500, &format!("{e:#}"))),
        "Decode" => match play_cap::decode_chain_hex(body["chain"].as_str().unwrap_or("")) {
            Ok(c) => {
                let mut d = play_cap::decode_for_display(&c);
                d["verify"] = match play_cap::verify_chain(&c, &s.root.verifying_key().to_bytes(), now()) {
                    Ok(_) => json!({ "ok": true }),
                    Err(e) => json!({ "ok": false, "error": e }),
                };
                Resp::ok(d)
            }
            Err(e) => Resp::error(400, &e),
        },
        op => Resp::error(404, &format!("play.grant@1 has no op {op}")),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("serve") {
        bail!("usage: play-grant serve [addr]");
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let data = std::env::var("PLAY_DATA").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(&home).join(".local/share/demo-playground"));
    let root = load_or_make_key(&data.join("grant/root.seed"))?;
    let issuer = load_or_make_key(&data.join("grant/issuer.seed"))?;
    // The root link is re-issued at every start: 30 days, any play ability, resource tag "play".
    let t = now();
    let root_link = play_cap::sign(
        &root,
        Capability {
            issuer: root.verifying_key().to_bytes(),
            audience: issuer.verifying_key().to_bytes(),
            abilities: vec!["play:*".into()],
            resource: Resource::Tag("play".into()),
            caveats: Caveats { not_after: t + 30 * 86400, max_credits: Some(MAX_CALLS), max_mem_mb: Some(32), ..Default::default() },
            nonce: t,
            parent: None,
        },
    );
    eprintln!("play.grant@1: root {}", hex::encode(root.verifying_key().to_bytes()));
    let svc = Arc::new(Svc { root, issuer, root_link, challenges: Mutex::new(HashMap::new()), per_ip: Mutex::new(HashMap::new()) });
    let addr = args.get(1).cloned().unwrap_or_else(|| "127.0.0.1:7861".into());
    play_http::serve(&addr, 4, Arc::new(move |r| handle(&svc, r)))
}
