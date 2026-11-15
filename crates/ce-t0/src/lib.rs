//! ce-t0: the T0 tier. Runs one call of an untrusted WebAssembly cell and returns its answer or the
//! trap that stopped it.
//!
//! T0 means: no network, no files, no environment, no host calls beyond reading the request on stdin
//! and writing the answer on stdout. Every call gets a fresh Store and instance with an instruction
//! budget (fuel), a linear-memory cap and a wall-clock deadline (epoch interruption). A guest that
//! imports anything else still loads, but the import is bound to a function that traps with a
//! message naming it, so the page can show exactly what was refused. WASI socket calls are bound
//! the same way.
//!
//! The cell protocol (T0 v0): stdin is `<op> <state>` where state is an i64; stdout is
//! `= <result> <new state>`, `! <error>`, or for op `__describe`, `ops <op1>,<op2>,...`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use wasmtime::{Config, Engine, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::WasiCtxBuilder;

/// The limits of one call. Defaults are the public playground's.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub fuel: u64,
    pub mem_mb: u64,
    pub deadline_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { fuel: 400_000_000, mem_mb: 32, deadline_ms: 2_000 }
    }
}

pub const MAX_STDOUT: usize = 4096;
const EPOCH_TICK_MS: u64 = 5;

#[derive(Debug, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The cell answered.
    Ok { result: i64, state: i64 },
    /// The cell refused the call itself (`! <error>`).
    Refused { error: String },
    /// `__describe`: the ops the cell answers.
    Ops { ops: Vec<String> },
    /// T0 stopped the cell.
    Trap { trap: String },
}

#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub outcome: Outcome,
    pub fuel_used: u64,
    pub ms: u64,
    pub limits: Limits,
}

pub fn engine() -> Result<Engine> {
    let mut c = Config::new();
    c.consume_fuel(true);
    c.epoch_interruption(true);
    // Small reservations so many jailed workers fit in one machine's address space.
    c.memory_reservation(64 << 20);
    c.memory_guard_size(64 << 10);
    Engine::new(&c).map_err(anyhow::Error::from)
}

/// Why each import a module asks for is or is not available in T0.
#[derive(Debug, Serialize)]
pub struct ImportRow {
    pub module: String,
    pub name: String,
    pub allowed: bool,
}

fn allowed_import(module: &str, name: &str) -> bool {
    module == "wasi_snapshot_preview1" && !name.starts_with("sock_")
}

pub fn imports(module: &Module) -> Vec<ImportRow> {
    module
        .imports()
        .map(|i| ImportRow {
            module: i.module().to_string(),
            name: i.name().to_string(),
            allowed: allowed_import(i.module(), i.name()) && matches!(i.ty(), ExternType::Func(_)),
        })
        .collect()
}

/// Compile and check a module; returns the precompiled bytes `run` loads.
pub fn compile(engine: &Engine, wasm: &[u8]) -> Result<Vec<u8>> {
    let module = Module::new(engine, wasm).map_err(anyhow::Error::from).context("not a valid WebAssembly module")?;
    for i in module.imports() {
        if !matches!(i.ty(), ExternType::Func(_)) {
            return Err(anyhow!("T0 refuses non-function import {}::{}", i.module(), i.name()));
        }
    }
    if module.get_export("_start").is_none() {
        return Err(anyhow!("cell does not export _start (build it as a WASI command)"));
    }
    module.serialize().map_err(anyhow::Error::from)
}

struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

fn denial(module: &str, name: &str) -> String {
    if name.starts_with("sock_") || name.contains("net") || name.contains("connect") || module.contains("socket") || module.contains("http") {
        format!("T0 trap: network call {module}::{name} denied (T0 cells have no network)")
    } else {
        format!("T0 trap: host call {module}::{name} denied (T0 offers only stdin, stdout, clocks and random)")
    }
}

/// Run one call. `module` is from [`load`] or `Module::new`.
pub fn run(engine: &Engine, module: &Module, op: &str, state: i64, limits: Limits) -> Report {
    let started = Instant::now();
    let (outcome, fuel_used) = match run_inner(engine, module, op, state, limits) {
        Ok(v) => v,
        Err((trap, used)) => (Outcome::Trap { trap }, used),
    };
    Report { outcome, fuel_used, ms: started.elapsed().as_millis() as u64, limits }
}

fn run_inner(engine: &Engine, module: &Module, op: &str, state: i64, limits: Limits) -> Result<(Outcome, u64), (String, u64)> {
    let stdout = MemoryOutputPipe::new(MAX_STDOUT);
    let stderr = MemoryOutputPipe::new(MAX_STDOUT);
    let wasi = WasiCtxBuilder::new()
        .stdin(MemoryInputPipe::new(format!("{op} {state}").into_bytes()))
        .stdout(stdout.clone())
        .stderr(stderr)
        .build_p1();
    let store_limits = StoreLimitsBuilder::new()
        .memory_size((limits.mem_mb as usize) << 20)
        .instances(1)
        .tables(4)
        .memories(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(engine, State { wasi, limits: store_limits });
    store.limiter(|s| &mut s.limits);
    store.set_fuel(limits.fuel).map_err(|e| (e.to_string(), 0))?;
    store.set_epoch_deadline(u64::MAX);

    let mut linker: Linker<State> = Linker::new(engine);
    linker.allow_shadowing(true);
    p1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi).map_err(|e| (e.to_string(), 0))?;
    for i in module.imports() {
        let (m, n) = (i.module().to_string(), i.name().to_string());
        let ExternType::Func(ty) = i.ty() else {
            return Err((format!("T0 refuses non-function import {m}::{n}"), 0));
        };
        if allowed_import(&m, &n) {
            continue;
        }
        let msg = denial(&m, &n);
        linker
            .func_new(&m, &n, ty, move |_c, _p, _r| Err(wasmtime::format_err!("{msg}")))
            .map_err(|e| (e.to_string(), 0))?;
    }

    let used = |store: &Store<State>| limits.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
    let instance = match linker.instantiate(&mut store, module) {
        Ok(i) => i,
        Err(e) => return Err((format!("T0 trap at start: {}", root_msg(&e.into())), used(&store))),
    };
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(|_| ("cell does not export _start".to_string(), 0))?;

    // Wall-clock deadline: a watchdog ticks the epoch; the store traps when it passes the deadline.
    store.set_epoch_deadline(limits.deadline_ms / EPOCH_TICK_MS + 1);
    let done = Arc::new(AtomicBool::new(false));
    let watchdog = {
        let (engine, done) = (engine.clone(), done.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
                engine.increment_epoch();
            }
        })
    };
    let res = start.call(&mut store, ());
    done.store(true, Ordering::Relaxed);
    let _ = watchdog.join();
    let fuel_used = used(&store);

    if let Err(e) = res {
        let e: anyhow::Error = e.into();
        match e.downcast_ref::<wasmtime_wasi::I32Exit>() {
            Some(x) if x.0 == 0 => {}
            Some(x) => return Err((format!("cell exited with code {}", x.0), fuel_used)),
            None => return Err((trap_text(&e, limits), fuel_used)),
        }
    }
    drop(store);
    let out = String::from_utf8_lossy(&stdout.contents()).trim().to_string();
    Ok((parse_answer(&out).map_err(|m| (m, fuel_used))?, fuel_used))
}

fn root_msg(e: &anyhow::Error) -> String {
    e.chain().map(|c| c.to_string()).find(|s| s.starts_with("T0 trap")).unwrap_or_else(|| format!("{e:#}"))
}

fn trap_text(e: &anyhow::Error, limits: Limits) -> String {
    if let Some(t) = e.downcast_ref::<wasmtime::Trap>() {
        return match t {
            wasmtime::Trap::OutOfFuel => format!("T0 trap: out of fuel ({} instructions)", limits.fuel),
            wasmtime::Trap::Interrupt => format!("T0 trap: deadline of {} ms passed", limits.deadline_ms),
            wasmtime::Trap::MemoryOutOfBounds => "T0 trap: memory access out of bounds".into(),
            wasmtime::Trap::AllocationTooLarge => format!("T0 trap: memory cap of {} MB reached", limits.mem_mb),
            wasmtime::Trap::UnreachableCodeReached => "T0 trap: the cell panicked (unreachable)".into(),
            other => format!("T0 trap: {other}"),
        };
    }
    let m = root_msg(e);
    if m.contains("memory") && m.contains("grow") {
        return format!("T0 trap: memory cap of {} MB reached", limits.mem_mb);
    }
    m
}

pub fn parse_answer(out: &str) -> Result<Outcome, String> {
    if let Some(rest) = out.strip_prefix("= ") {
        let mut it = rest.split_whitespace();
        let r = it.next().and_then(|s| s.parse().ok());
        let s = it.next().and_then(|s| s.parse().ok());
        if let (Some(result), Some(state)) = (r, s) {
            return Ok(Outcome::Ok { result, state });
        }
    } else if let Some(e) = out.strip_prefix("! ") {
        return Ok(Outcome::Refused { error: e.chars().take(300).collect() });
    } else if let Some(ops) = out.strip_prefix("ops ") {
        let ops: Vec<String> = ops.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if ops.iter().all(|o| o.len() <= 32 && o.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')) && ops.len() <= 16 {
            return Ok(Outcome::Ops { ops });
        }
        return Err("cell described ops with invalid names (letters, digits and _ only, at most 16)".into());
    }
    Err(format!("cell answered outside the T0 protocol: {:?}", out.chars().take(120).collect::<String>()))
}

/// Load a module precompiled by [`compile`] with the same ce-t0 binary.
///
/// # Safety
/// The file must come from [`compile`] of this exact build (cell.host only passes its own outputs).
pub unsafe fn load(engine: &Engine, cwasm: &[u8]) -> Result<Module> {
    Module::deserialize(engine, cwasm).map_err(anyhow::Error::from)
}

/// The jail every untrusted step runs in: no network, no other processes, no home directory, a
/// fresh /tmp, only /usr plus the paths in `binds` (read-only `(host, inside)` pairs), a CPU-time
/// and file-size limit. `rw` is one read-write directory mounted at /build, if any.
pub fn jail(binds: &[(&std::path::Path, &str)], rw: Option<&std::path::Path>, cpu_s: u64, argv: &[&str]) -> std::process::Command {
    let mut c = std::process::Command::new("prlimit");
    c.arg(format!("--cpu={cpu_s}")).arg("--fsize=67108864").arg("--core=0").arg("--");
    c.arg("bwrap");
    c.args(["--unshare-all", "--die-with-parent", "--new-session", "--clearenv"]);
    c.args(["--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/bin", "/bin"]);
    if std::path::Path::new("/usr/lib64").exists() {
        c.args(["--symlink", "usr/lib64", "/lib64"]);
    }
    c.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--setenv", "HOME", "/tmp"]);
    c.args(["--setenv", "PATH", "/toolchain/bin:/usr/bin"]);
    for (host, inside) in binds {
        c.arg("--ro-bind").arg(host).arg(inside);
    }
    if let Some(dir) = rw {
        c.arg("--bind").arg(dir).arg("/build").args(["--chdir", "/build"]);
    }
    c.args(argv);
    c.env_clear().env("PATH", "/usr/bin:/bin");
    c
}

/// Run `ce-t0 run` for one call inside [`jail`]; returns its JSON report.
pub fn jailed_call(t0_bin: &std::path::Path, cell: &std::path::Path, op: &str, state: i64, limits: Limits) -> Result<serde_json::Value> {
    let inside = if cell.extension().is_some_and(|e| e == "cwasm") { "/cell.cwasm" } else { "/cell.wasm" };
    let (fuel, mem, dl) = (limits.fuel.to_string(), limits.mem_mb.to_string(), limits.deadline_ms.to_string());
    let state = state.to_string();
    let argv = ["/t0", "run", inside, op, &state, "--fuel", &fuel, "--mem-mb", &mem, "--deadline-ms", &dl];
    let out = jail(&[(t0_bin, "/t0"), (cell, inside)], None, 10, &argv)
        .stdin(std::process::Stdio::null())
        .output()
        .context("start the T0 jail (needs bwrap and prlimit)")?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(text.trim()).with_context(|| {
        format!("T0 worker gave no report (status {}): {}", out.status, String::from_utf8_lossy(&out.stderr).chars().take(300).collect::<String>())
    })
}
