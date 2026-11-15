//! ce-t0 worker. Holds no key and opens no socket; cell.host runs it inside a jail with only the
//! cell file mapped in.
//!
//!   ce-t0 compile <cell.wasm> <cell.cwasm>      check and precompile; prints the imports as JSON
//!   ce-t0 run <cell.cwasm|cell.wasm> <op> <state> [--fuel N] [--mem-mb N] [--deadline-ms N]
//!                                                one call; prints the report as JSON

use anyhow::{bail, Context, Result};

fn main() {
    if let Err(e) = real_main() {
        println!("{}", serde_json::json!({ "kind": "error", "error": format!("{e:#}") }));
        std::process::exit(2);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let engine = ce_t0::engine()?;
    match args.first().map(String::as_str) {
        Some("compile") if args.len() == 3 => {
            let wasm = std::fs::read(&args[1]).context("read cell")?;
            let cwasm = ce_t0::compile(&engine, &wasm)?;
            std::fs::write(&args[2], cwasm).context("write precompiled cell")?;
            let module = wasmtime::Module::new(&engine, &wasm).map_err(anyhow::Error::from)?;
            println!("{}", serde_json::json!({ "kind": "compiled", "imports": ce_t0::imports(&module) }));
            Ok(())
        }
        Some("run") if args.len() >= 4 => {
            let mut limits = ce_t0::Limits::default();
            let mut i = 4;
            while i < args.len() {
                let v: u64 = args.get(i + 1).context("flag needs a value")?.parse().context("flag value")?;
                match args[i].as_str() {
                    "--fuel" => limits.fuel = v,
                    "--mem-mb" => limits.mem_mb = v,
                    "--deadline-ms" => limits.deadline_ms = v,
                    f => bail!("unknown flag {f}"),
                }
                i += 2;
            }
            let state: i64 = args[3].parse().context("state must be an i64")?;
            let bytes = std::fs::read(&args[1]).context("read cell")?;
            let module = if args[1].ends_with(".cwasm") {
                // SAFETY: cell.host passes only files this binary's `compile` wrote.
                unsafe { ce_t0::load(&engine, &bytes)? }
            } else {
                wasmtime::Module::new(&engine, &bytes).map_err(anyhow::Error::from)?
            };
            let report = ce_t0::run(&engine, &module, &args[2], state, limits);
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        _ => bail!("usage: ce-t0 compile <in.wasm> <out.cwasm> | ce-t0 run <cell> <op> <state> [--fuel N] [--mem-mb N] [--deadline-ms N]"),
    }
}
