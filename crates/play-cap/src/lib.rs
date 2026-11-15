//! The ce-net capability token (format v1, domain tag `ce-cap-v1`), written from the published byte
//! layout so the playground can issue and check guest chains with crates.io dependencies only.
//!
//! A chain is a list of Ed25519-signed links, root first. Each link names its issuer, its holder
//! (audience), the abilities it grants, a resource, caveats (time window and ceilings) and the hash
//! of its parent link. A child link may only narrow its parent. The hex token produced here is
//! byte-compatible with ce-cap, so any ce-cap verifier accepts it (see the golden-vector test).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const CAP_DOMAIN: &str = "ce-cap-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum Resource {
    Any,
    Node(#[serde(with = "hex32")] [u8; 32]),
    Tag(String),
    AllOf(Vec<String>),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Caveats {
    pub not_before: u64,
    pub not_after: u64,
    pub max_cpu: Option<u32>,
    pub max_mem_mb: Option<u32>,
    pub max_credits: Option<u64>,
    pub allowed_ports: Option<Vec<u16>>,
    pub path_prefix: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Capability {
    #[serde(with = "hex32")]
    pub issuer: [u8; 32],
    #[serde(with = "hex32")]
    pub audience: [u8; 32],
    pub abilities: Vec<String>,
    pub resource: Resource,
    pub caveats: Caveats,
    pub nonce: u64,
    #[serde(with = "hex32opt")]
    pub parent: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCapability {
    pub cap: Capability,
    pub sig: [u8; 64],
}

pub type Chain = Vec<SignedCapability>;

// ---- encoding (bincode 1 default: little-endian fixed ints, u64 lengths) ----

fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&(n as u64).to_le_bytes());
}
fn put_str(out: &mut Vec<u8>, s: &str) {
    put_len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn encode_cap(out: &mut Vec<u8>, c: &Capability) {
    out.extend_from_slice(&c.issuer);
    out.extend_from_slice(&c.audience);
    put_len(out, c.abilities.len());
    for a in &c.abilities {
        put_str(out, a);
    }
    match &c.resource {
        Resource::Any => out.extend_from_slice(&0u32.to_le_bytes()),
        Resource::Node(n) => {
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(n);
        }
        Resource::Tag(t) => {
            out.extend_from_slice(&2u32.to_le_bytes());
            put_str(out, t);
        }
        Resource::AllOf(ts) => {
            out.extend_from_slice(&3u32.to_le_bytes());
            put_len(out, ts.len());
            for t in ts {
                put_str(out, t);
            }
        }
    }
    let k = &c.caveats;
    out.extend_from_slice(&k.not_before.to_le_bytes());
    out.extend_from_slice(&k.not_after.to_le_bytes());
    opt(out, &k.max_cpu, |o, v| o.extend_from_slice(&v.to_le_bytes()));
    opt(out, &k.max_mem_mb, |o, v| o.extend_from_slice(&v.to_le_bytes()));
    opt(out, &k.max_credits, |o, v| o.extend_from_slice(&v.to_le_bytes()));
    opt(out, &k.allowed_ports, |o, v| {
        put_len(o, v.len());
        for p in v {
            o.extend_from_slice(&p.to_le_bytes());
        }
    });
    opt(out, &k.path_prefix, |o, v| put_str(o, v));
    out.extend_from_slice(&c.nonce.to_le_bytes());
    opt(out, &c.parent, |o, v| o.extend_from_slice(v));
}

fn opt<T>(out: &mut Vec<u8>, v: &Option<T>, f: impl FnOnce(&mut Vec<u8>, &T)) {
    match v {
        None => out.push(0),
        Some(x) => {
            out.push(1);
            f(out, x);
        }
    }
}

/// The bytes the issuer signs: the length-prefixed domain tag, then the capability.
pub fn cap_bytes(c: &Capability) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    put_str(&mut out, CAP_DOMAIN);
    encode_cap(&mut out, c);
    out
}

pub fn cap_id(c: &Capability) -> [u8; 32] {
    Sha256::digest(cap_bytes(c)).into()
}

pub fn sign(key: &SigningKey, cap: Capability) -> SignedCapability {
    let sig = key.sign(&cap_bytes(&cap)).to_bytes();
    SignedCapability { cap, sig }
}

pub fn encode_chain(chain: &[SignedCapability]) -> Vec<u8> {
    let mut out = Vec::new();
    put_len(&mut out, chain.len());
    for l in chain {
        encode_cap(&mut out, &l.cap);
        put_len(&mut out, 64);
        out.extend_from_slice(&l.sig);
    }
    out
}

pub fn chain_hex(chain: &[SignedCapability]) -> String {
    hex::encode(encode_chain(chain))
}

// ---- decoding ----

struct R<'a> {
    b: &'a [u8],
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.b.len() < n {
            return Err("token is truncated".into());
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn len(&mut self) -> Result<usize, String> {
        let n = self.u64()?;
        // Every element takes at least one byte, so a length above what is left is a lie.
        if n > self.b.len() as u64 {
            return Err("length prefix exceeds the token".into());
        }
        Ok(n as usize)
    }
    fn b32(&mut self) -> Result<[u8; 32], String> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn string(&mut self) -> Result<String, String> {
        let n = self.len()?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "invalid UTF-8 in token".into())
    }
    fn opt<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, String>) -> Result<Option<T>, String> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            _ => Err("bad option tag".into()),
        }
    }
}

fn decode_cap(r: &mut R) -> Result<Capability, String> {
    let issuer = r.b32()?;
    let audience = r.b32()?;
    let n = r.len()?;
    let mut abilities = Vec::with_capacity(n);
    for _ in 0..n {
        abilities.push(r.string()?);
    }
    let resource = match r.u32()? {
        0 => Resource::Any,
        1 => Resource::Node(r.b32()?),
        2 => Resource::Tag(r.string()?),
        3 => {
            let n = r.len()?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(r.string()?);
            }
            Resource::AllOf(v)
        }
        _ => return Err("bad resource tag".into()),
    };
    let caveats = Caveats {
        not_before: r.u64()?,
        not_after: r.u64()?,
        max_cpu: r.opt(|r| r.u32())?,
        max_mem_mb: r.opt(|r| r.u32())?,
        max_credits: r.opt(|r| r.u64())?,
        allowed_ports: r.opt(|r| {
            let n = r.len()?;
            (0..n).map(|_| r.u16()).collect()
        })?,
        path_prefix: r.opt(|r| r.string())?,
    };
    let nonce = r.u64()?;
    let parent = r.opt(|r| r.b32())?;
    Ok(Capability { issuer, audience, abilities, resource, caveats, nonce, parent })
}

pub fn decode_chain(bytes: &[u8]) -> Result<Chain, String> {
    let mut r = R { b: bytes };
    let n = r.len()?;
    let mut chain = Vec::with_capacity(n);
    for _ in 0..n {
        let cap = decode_cap(&mut r)?;
        if r.u64()? != 64 {
            return Err("signature length is not 64".into());
        }
        let sig: [u8; 64] = r.take(64)?.try_into().unwrap();
        chain.push(SignedCapability { cap, sig });
    }
    Ok(chain)
}

pub fn decode_chain_hex(s: &str) -> Result<Chain, String> {
    let bytes = hex::decode(s.trim()).map_err(|_| "token is not hex".to_string())?;
    decode_chain(&bytes)
}

// ---- verification (verify_chain of the format spec, section 8) ----

pub fn covers(granted: &str, needed: &str) -> bool {
    if granted == needed || granted == "*" {
        return true;
    }
    if let Some(p) = granted.strip_suffix('*') {
        if p.ends_with(':') {
            return needed.starts_with(p) && needed.len() > p.len();
        }
    }
    false
}

fn resource_subset(child: &Resource, parent: &Resource) -> bool {
    match (parent, child) {
        (Resource::Any, _) => true,
        (Resource::Node(p), Resource::Node(c)) => p == c,
        (Resource::Tag(t), Resource::Tag(c)) => t == c,
        (Resource::Tag(t), Resource::AllOf(s)) => s.contains(t),
        (Resource::AllOf(ps), Resource::AllOf(s)) => ps.iter().all(|p| s.contains(p)),
        (Resource::AllOf(ps), Resource::Tag(s)) => ps.iter().all(|p| p == s),
        _ => false,
    }
}

fn ceiling<T: PartialOrd>(c: &Option<T>, p: &Option<T>) -> bool {
    match (p, c) {
        (None, _) => true,
        (Some(p), Some(c)) => c <= p,
        (Some(_), None) => false,
    }
}

fn within(child: &str, parent: &str) -> bool {
    let c = child.trim_end_matches('/');
    let p = parent.trim_end_matches('/');
    p.is_empty() || c == p || c.starts_with(&format!("{p}/"))
}

fn caveats_narrower(c: &Caveats, p: &Caveats) -> bool {
    if p.not_after != 0 && (c.not_after == 0 || c.not_after > p.not_after) {
        return false;
    }
    if c.not_before < p.not_before {
        return false;
    }
    if !ceiling(&c.max_cpu, &p.max_cpu)
        || !ceiling(&c.max_mem_mb, &p.max_mem_mb)
        || !ceiling(&c.max_credits, &p.max_credits)
    {
        return false;
    }
    if let Some(pp) = &p.allowed_ports {
        match &c.allowed_ports {
            Some(cp) if cp.iter().all(|x| pp.contains(x)) => {}
            _ => return false,
        }
    }
    if let Some(pp) = &p.path_prefix {
        match &c.path_prefix {
            Some(cp) if within(cp, pp) => {}
            _ => return false,
        }
    }
    true
}

/// Checks the chain against `root` at `now`; on success returns the leaf (what the holder may use).
pub fn verify_chain(chain: &[SignedCapability], root: &[u8; 32], now: u64) -> Result<Capability, String> {
    let first = chain.first().ok_or("no capability presented")?;
    if &first.cap.issuer != root {
        return Err("capability chain does not root at an accepted authority".into());
    }
    for (i, l) in chain.iter().enumerate() {
        let vk = VerifyingKey::from_bytes(&l.cap.issuer).map_err(|_| format!("link {i}: invalid signature"))?;
        vk.verify(&cap_bytes(&l.cap), &Signature::from_bytes(&l.sig))
            .map_err(|_| format!("link {i}: invalid signature"))?;
        let k = &l.cap.caveats;
        if k.not_before != 0 && now < k.not_before {
            return Err(format!("link {i}: capability not yet valid"));
        }
        if k.not_after != 0 && now > k.not_after {
            return Err(format!("link {i}: capability has expired"));
        }
        if i == 0 {
            if l.cap.parent.is_some() {
                return Err("root capability must not name a parent".into());
            }
        } else {
            let p = &chain[i - 1].cap;
            if l.cap.issuer != p.audience {
                return Err(format!("link {i}: issuer is not the parent's audience"));
            }
            if l.cap.parent != Some(cap_id(p)) {
                return Err(format!("link {i}: parent hash does not match the chain"));
            }
            if !l.cap.abilities.iter().all(|a| p.abilities.iter().any(|g| covers(g, a))) {
                return Err(format!("link {i}: abilities exceed the parent"));
            }
            if !resource_subset(&l.cap.resource, &p.resource) {
                return Err(format!("link {i}: resource is broader than the parent"));
            }
            if !caveats_narrower(&l.cap.caveats, &p.caveats) {
                return Err(format!("link {i}: caveats are broader than the parent"));
            }
        }
    }
    Ok(chain.last().unwrap().cap.clone())
}

/// A readable view of a chain for the page: every field of every link, plus its id.
pub fn decode_for_display(chain: &[SignedCapability]) -> serde_json::Value {
    let links: Vec<_> = chain
        .iter()
        .map(|l| {
            let mut v = serde_json::to_value(&l.cap).unwrap();
            v["cap_id"] = hex::encode(cap_id(&l.cap)).into();
            v["sig"] = hex::encode(l.sig).into();
            v
        })
        .collect();
    serde_json::json!({ "format": "ce-cap-v1", "links": links })
}

pub fn key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

pub fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("os random");
    s
}

/// The message a holder signs to prove it owns the leaf key of a playground chain.
pub fn call_message(target: &str, op: &str, ts: u64) -> String {
    format!("play-call-v0\n{target}\n{op}\n{ts}")
}

pub fn verify_holder(audience: &[u8; 32], msg: &str, sig_hex: &str) -> Result<(), String> {
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("holder signature is not 64 bytes of hex")?;
    let vk = VerifyingKey::from_bytes(audience).map_err(|_| "leaf audience is not a key")?;
    vk.verify(msg.as_bytes(), &Signature::from_bytes(&sig)).map_err(|_| "holder signature does not match the leaf key".to_string())
}

/// How far a request's timestamp may be from the verifier's clock.
pub const MAX_SKEW_S: u64 = 120;

/// Check a playground request: `grant` is `{chain, ts, sig}` where `sig` is the leaf key's
/// signature over [`call_message`]`(target, op, ts)`. The chain must root at `root`, be valid now,
/// and its leaf must grant `ability`. Returns the leaf.
pub fn authorize_request(
    grant: &serde_json::Value,
    root: &[u8; 32],
    now: u64,
    ability: &str,
    target: &str,
    op: &str,
) -> Result<Capability, String> {
    let chain = decode_chain_hex(grant["chain"].as_str().ok_or("request carries no guest grant")?)?;
    let leaf = verify_chain(&chain, root, now)?;
    if !leaf.abilities.iter().any(|a| covers(a, ability)) {
        return Err(format!("capability does not grant '{ability}'"));
    }
    let ts = grant["ts"].as_u64().ok_or("grant has no ts")?;
    if ts.abs_diff(now) > MAX_SKEW_S {
        return Err("request timestamp is too far from the host clock".into());
    }
    verify_holder(&leaf.audience, &call_message(target, op, ts), grant["sig"].as_str().unwrap_or(""))?;
    Ok(leaf)
}

mod hex32 {
    pub fn serialize<S: serde::Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
}
mod hex32opt {
    pub fn serialize<S: serde::Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&hex::encode(v)),
            None => s.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector "issued" from the ce-cap v1 golden vectors: root seed 01x32, audience seed 02x32.
    const CHAIN_HEX: &str = "01000000000000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940200000000000000040000000000000065786563040000000000000073796e63000000000000000000000000000000000000000000000000000100000000000000004000000000000000eac5311cbaf19127b73ba42f33e13da516073a46ddc343d8f703ad7845378805e662b56d7db7af8163b0e3e735ba83e4d2fd2be0d66ebbd6db1986c2a0a90b08";
    const CAP_ID: &str = "f7929567c12bb7600130b8a0a97c370c6e5af04114f57f0d32412d73c1cca920";

    #[test]
    fn golden_vector_round_trips() {
        let root = key_from_seed(&[1; 32]);
        let aud = key_from_seed(&[2; 32]).verifying_key().to_bytes();
        let cap = Capability {
            issuer: root.verifying_key().to_bytes(),
            audience: aud,
            abilities: vec!["exec".into(), "sync".into()],
            resource: Resource::Any,
            caveats: Caveats::default(),
            nonce: 1,
            parent: None,
        };
        assert_eq!(hex::encode(cap_id(&cap)), CAP_ID);
        let chain = vec![sign(&root, cap)];
        assert_eq!(chain_hex(&chain), CHAIN_HEX);
        let back = decode_chain_hex(CHAIN_HEX).unwrap();
        assert_eq!(back, chain);
        verify_chain(&back, &root.verifying_key().to_bytes(), 1_700_000_000).unwrap();
    }

    fn two_links(child_caveats: Caveats, child_abilities: Vec<String>) -> (Chain, [u8; 32]) {
        let root = key_from_seed(&[1; 32]);
        let mid = key_from_seed(&[2; 32]);
        let leaf = key_from_seed(&[3; 32]).verifying_key().to_bytes();
        let c0 = Capability {
            issuer: root.verifying_key().to_bytes(),
            audience: mid.verifying_key().to_bytes(),
            abilities: vec!["play:*".into()],
            resource: Resource::Tag("play".into()),
            caveats: Caveats { not_after: 2_000, max_credits: Some(100), ..Default::default() },
            nonce: 1,
            parent: None,
        };
        let c1 = Capability {
            issuer: mid.verifying_key().to_bytes(),
            audience: leaf,
            abilities: child_abilities,
            resource: Resource::Tag("play".into()),
            caveats: child_caveats,
            nonce: 7,
            parent: Some(cap_id(&c0)),
        };
        (vec![sign(&root, c0), sign(&mid, c1)], root.verifying_key().to_bytes())
    }

    #[test]
    fn attenuation_is_enforced() {
        let ok = Caveats { not_after: 1_500, max_credits: Some(50), ..Default::default() };
        let (chain, root) = two_links(ok.clone(), vec!["play:call".into()]);
        assert!(verify_chain(&chain, &root, 1_000).is_ok());
        assert_eq!(verify_chain(&chain, &root, 1_600).unwrap_err(), "link 1: capability has expired");
        let (chain, root) = two_links(ok.clone(), vec!["admin".into()]);
        assert_eq!(verify_chain(&chain, &root, 1_000).unwrap_err(), "link 1: abilities exceed the parent");
        let wide = Caveats { not_after: 1_500, max_credits: Some(500), ..Default::default() };
        let (chain, root) = two_links(wide, vec!["play:call".into()]);
        assert_eq!(verify_chain(&chain, &root, 1_000).unwrap_err(), "link 1: caveats are broader than the parent");
        let (mut chain, root) = two_links(ok, vec!["play:call".into()]);
        chain[1].cap.caveats.max_credits = Some(10);
        assert_eq!(verify_chain(&chain, &root, 1_000).unwrap_err(), "link 1: invalid signature");
    }

    #[test]
    fn holder_proof() {
        let k = key_from_seed(&[9; 32]);
        let msg = call_message("i1", "incr", 5);
        let sig = hex::encode(k.sign(msg.as_bytes()).to_bytes());
        verify_holder(&k.verifying_key().to_bytes(), &msg, &sig).unwrap();
        assert!(verify_holder(&k.verifying_key().to_bytes(), &call_message("i1", "get", 5), &sig).is_err());
    }
}
