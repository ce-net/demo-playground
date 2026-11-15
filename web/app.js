// Playground page. Talks only to this origin's /api, which routes each call to one cell:
// play.grant@1, build.wasm@1, cell.host, client.gen@1.
"use strict";
const $ = (id) => document.getElementById(id);
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();
const S = { grant: null, templates: [], tpl: null, cell: null, lang: "ts", kind: { ttl: 600, calls: 50 } };

// ---- theme (dark default, light only by the switch) ----
try { if (localStorage.getItem("ce-theme") === "light") document.documentElement.dataset.theme = "light"; } catch (_) {}
const themeBtn = $("theme");
const syncTheme = () => { themeBtn.textContent = document.documentElement.dataset.theme === "light" ? "Dark" : "Light"; };
themeBtn.onclick = () => {
  const light = document.documentElement.dataset.theme !== "light";
  if (light) document.documentElement.dataset.theme = "light"; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem("ce-theme", light ? "light" : "dark"); } catch (_) {}
  syncTheme();
};
syncTheme();

async function api(path, body) {
  const r = await fetch("/api/" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
  let v; try { v = await r.json(); } catch (_) { v = { error: "no answer (" + r.status + ")" }; }
  return { ok: r.ok, status: r.status, v };
}
const now = () => Math.floor(Date.now() / 1000);
const when = (t) => {
  const d = new Date(t * 1000), o = { hour: "2-digit", minute: "2-digit", second: "2-digit" };
  return Math.abs(t - Date.now() / 1000) > 86400 ? d.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], o) : d.toLocaleTimeString([], o);
};
const short = (h) => h ? h.slice(0, 10) + "…" + h.slice(-6) : "";
function setStatus(el, text, cls) { el.textContent = text; el.className = "status" + (cls ? " " + cls : ""); }

// ---- pills ----
function pills(group, onPick) {
  group.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    group.querySelectorAll("button").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
    onPick(b);
  }));
}
pills(document.querySelector('[aria-label="Grant kind"]'), (b) => { S.kind = { ttl: +b.dataset.ttl, calls: +b.dataset.calls }; });
pills($("langs"), (b) => { S.lang = b.dataset.lang; genClient(); });

// ---- templates ----
async function loadTemplates() {
  const { ok, v } = await api("templates");
  if (!ok) { setStatus($("deploy-status"), "templates unavailable: " + v.error, "bad"); return; }
  S.templates = v;
  const box = $("templates");
  box.innerHTML = "";
  v.forEach((t, i) => {
    const b = document.createElement("button");
    b.innerHTML = "<i></i>" + (t.lang === "rust" ? "Rust" : "JS") + " · " + t.name;
    b.onclick = () => pick(i);
    box.appendChild(b);
  });
  pick(0);
}
function pick(i) {
  S.tpl = S.templates[i];
  $("src").value = S.tpl.src;
  [...$("templates").children].forEach((b, j) => b.classList.toggle("on", i === j));
}

// ---- guest grant: keypair here, proof-of-work captcha, chain from play.grant ----
async function pow(challenge, bits) {
  const full = bits >> 3, rest = bits & 7;
  for (let n = 0; ; n++) {
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(challenge + ":" + n)));
    let ok = true;
    for (let i = 0; i < full; i++) if (h[i] !== 0) { ok = false; break; }
    if (ok && rest && (h[full] >> (8 - rest)) !== 0) ok = false;
    if (ok) return String(n);
    if (n % 4000 === 0) setStatus($("grant-status"), "solving captcha · " + n + " hashes");
  }
}
$("b-grant").onclick = async () => {
  const st = $("grant-status");
  $("b-grant").disabled = true;
  try {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const pub = hex(await crypto.subtle.exportKey("raw", kp.publicKey));
    const seed = hex((await crypto.subtle.exportKey("pkcs8", kp.privateKey)).slice(-32));
    const c = await api("grant/challenge");
    if (!c.ok) throw new Error(c.v.error);
    const t0 = performance.now();
    const nonce = await pow(c.v.challenge, c.v.bits);
    const g = await api("grant/guest", { challenge: c.v.challenge, nonce, guest_pub: pub, ttl_s: S.kind.ttl, calls: S.kind.calls });
    if (!g.ok) throw new Error(g.v.error);
    S.grant = { key: kp.privateKey, pub, seed, chain: g.v.cap_chain, notAfter: g.v.not_after, quota: g.v.quota.calls };
    setStatus(st, "granted in " + Math.round(performance.now() - t0) + " ms · " + g.v.quota.calls + " calls until " + when(g.v.not_after), "good");
    showChain(g.v.decoded);
    $("grantstr").textContent = seed + "." + g.v.cap_chain;
    $("b-deploy").disabled = false;
    setStatus($("deploy-status"), "ready");
    stats();
  } catch (e) {
    setStatus(st, "grant refused: " + e.message, "bad");
  } finally { $("b-grant").disabled = false; }
};

function showChain(d) {
  const box = $("chain");
  box.innerHTML = "";
  d.links.forEach((l, i) => {
    const k = l.caveats;
    const div = document.createElement("div");
    div.className = "link fade-in";
    const rows = [
      ["Issuer", l.issuer], ["Holder", l.audience + (i === d.links.length - 1 ? "  (this browser)" : "")],
      ["Abilities", l.abilities.join(", ")], ["Resource", l.resource.kind + (l.resource.value ? " " + l.resource.value : "")],
      ["Not after", k.not_after ? when(k.not_after) + "  (" + k.not_after + ")" : "never"],
      ["Call quota", k.max_credits == null ? "none" : k.max_credits], ["Memory cap", k.max_mem_mb == null ? "none" : k.max_mem_mb + " MB"],
      ["Nonce", l.nonce], ["Parent", l.parent || "none (root link)"], ["Link id", l.cap_id],
    ];
    div.innerHTML = "<h4>Link " + i + (i === 0 ? " · playground root to issuer" : " · issuer to you") + "</h4>";
    const dl = document.createElement("dl"); dl.className = "kv";
    rows.forEach(([a, b]) => { const dt = document.createElement("dt"); dt.textContent = a; const dd = document.createElement("dd"); dd.textContent = b; dl.append(dt, dd); });
    div.appendChild(dl);
    box.appendChild(div);
  });
  const f = document.createElement("div"); f.className = "status"; f.style.marginTop = "8px";
  f.textContent = "format " + d.format + " · Ed25519 · each link may only narrow its parent";
  box.appendChild(f);
}

async function signed(target, op) {
  const ts = now();
  const sig = hex(await crypto.subtle.sign("Ed25519", S.grant.key, enc.encode("play-call-v0\n" + target + "\n" + op + "\n" + ts)));
  return { chain: S.grant.chain, ts, sig };
}

// ---- build and deploy ----
$("b-deploy").onclick = async () => {
  const st = $("deploy-status");
  $("b-deploy").disabled = true;
  try {
    setStatus(st, "building in the jail…");
    const src = $("src").value;
    const b = await api("build", { lang: S.tpl.lang, src, grant: await signed("build", "Build") });
    if (!b.ok) throw new Error(b.v.error);
    showArtifact(b.v, src);
    setStatus(st, "built in " + b.v.ms + " ms · deploying…");
    const d = await api("deploy", { artifact_sha256: b.v.artifact_sha256, descriptor: b.v.descriptor, grant: await signed(b.v.artifact_sha256, "Deploy") });
    if (!d.ok) throw new Error(d.v.error);
    S.cell = { id: d.v.instance, desc: b.v.descriptor, notAfter: d.v.not_after, used: d.v.calls_used, quota: d.v.quota, status: "live" };
    setStatus(st, "live as " + d.v.instance + " · built " + b.v.ms + " ms", "good");
    showOps();
    stats();
    genClient();
  } catch (e) {
    setStatus(st, e.message.split("\n").slice(0, 6).join(" "), "bad");
  } finally { $("b-deploy").disabled = false; }
};

function showArtifact(b, src) {
  const d = b.descriptor;
  const dl = $("art");
  dl.innerHTML = "";
  const add = (k, v, href) => {
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd");
    if (href) { const a = document.createElement("a"); a.href = href; a.textContent = v; dd.appendChild(a); } else dd.textContent = v;
    dl.append(dt, dd);
  };
  add("Artifact", d.artifact.sha256, "/api/blob/" + d.artifact.sha256);
  add("Size", (d.artifact.bytes / 1024).toFixed(1) + " KB · tier " + d.tier);
  add("Source", d.source.sha256, "/api/blob/" + d.source.sha256);
  add("Toolchain", d.toolchain.name + (d.toolchain.target ? " · " + d.toolchain.target : ""));
  add("Ops", d.ops.join(", "));
  $("desc").textContent = JSON.stringify(d, null, 2);
  const file = d.source.file;
  $("rebuild").textContent =
    "git clone https://github.com/ce-net/demo-playground && cd demo-playground\n" +
    "curl -so descriptor.json " + location.origin + "/api/blob/" + b.descriptor_sha256 + "\n" +
    "curl -so " + file + " " + location.origin + "/api/blob/" + d.source.sha256 + "\n" +
    "cargo build --release && target/release/build-wasm rebuild descriptor.json " + file + "\n" +
    "# prints MATCH when your build gives " + short(d.artifact.sha256);
}

function showOps() {
  const box = $("ops");
  box.innerHTML = "";
  S.cell.desc.ops.forEach((op) => {
    const b = document.createElement("button");
    b.className = "btn"; b.textContent = op;
    b.onclick = () => callOp(op);
    box.appendChild(b);
  });
}

function log(cls, op, text, extra) {
  const li = document.createElement("li");
  li.className = cls + " fade-in";
  const b = document.createElement("b"); b.textContent = op;
  const s = document.createElement("span"); s.textContent = text;
  if (extra) { const sm = document.createElement("small"); sm.textContent = "  " + extra; s.appendChild(sm); }
  li.append(b, s);
  $("log").prepend(li);
}

async function callOp(op) {
  if (!S.cell) return;
  const r = await api("call", { instance: S.cell.id, op, grant: await signed(S.cell.id, op) });
  if (!r.ok) { log("refused", op, r.v.error, "HTTP " + r.status); return; }
  const rep = r.v.report;
  S.cell.used = r.v.calls_used; S.cell.quota = r.v.quota;
  const extra = rep.fuel_used.toLocaleString() + " fuel · " + rep.ms + " ms";
  if (rep.kind === "ok") log("ok", op, "= " + rep.result, extra);
  else if (rep.kind === "trap") log("trap", op, rep.trap, extra);
  else log("refused", op, rep.error || rep.kind, extra);
  stats();
}

// ---- client.gen ----
async function genClient() {
  if (!S.cell) return;
  const r = await api("client", { descriptor: S.cell.desc, lang: S.lang, instance: S.cell.id });
  if (!r.ok) { $("usage").textContent = r.v.error; return; }
  $("usage").textContent = r.v.usage;
  $("module").textContent = r.v.module;
  $("modname").textContent = "(" + r.v.file + ")";
}

// ---- stats: quota ring and expiry ----
function stats() {
  const g = S.grant, c = S.cell;
  const quota = c ? c.quota : g ? g.quota : 0, used = c ? c.used : 0;
  const left = Math.max(0, quota - used);
  $("s-left").textContent = g ? left : "-";
  $("s-left-sub").textContent = g ? used + " of " + quota + " used" : "no grant yet";
  $("ring").setAttribute("stroke-dashoffset", String(94.25 * (1 - (quota ? left / quota : 0))));
  const end = c ? c.notAfter : g ? g.notAfter : 0;
  const secs = end - now();
  $("s-exp").textContent = !end ? "-" : secs > 0 ? Math.floor(secs / 60) + ":" + String(secs % 60).padStart(2, "0") : "expired";
  $("s-exp").classList.toggle("bad", !!end && secs <= 0);
  $("s-cell").textContent = c ? c.id : "none";
  $("s-cell-sub").textContent = c ? c.status + " · " + c.desc.lang : "not deployed";
  $("s-dot").className = c && c.status === "live" ? "g" : "r";
  $("hl").textContent = c ? "cell " + c.id + " " + c.status : g ? "guest grant until " + when(g.notAfter) : "deploy a cell from your browser";
}
setInterval(stats, 1000);
setInterval(async () => {
  if (!S.cell) return;
  const r = await api("usage", { instance: S.cell.id });
  if (r.ok) { S.cell.status = r.v.status; S.cell.used = r.v.calls_used; stats(); }
}, 3000);

loadTemplates();
