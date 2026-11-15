//! T0 limits on hand-written modules: the protocol, a network import, fuel, memory and the deadline.

use ce_t0::{engine, run, Limits, Outcome};
use wasmtime::Module;

/// A WASI command that writes `text` to stdout, after running `body` (WAT instructions).
fn cell(imports: &str, body: &str, text: &str) -> Vec<u8> {
    let len = text.len();
    wat::parse_str(format!(
        r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func $w (param i32 i32 i32 i32) (result i32)))
            {imports}
            (memory (export "memory") 1)
            (data (i32.const 64) "{text}")
            (func (export "_start")
              {body}
              (i32.store (i32.const 0) (i32.const 64))
              (i32.store (i32.const 4) (i32.const {len}))
              (drop (call $w (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))"#
    ))
    .unwrap()
}

fn go(wasm: &[u8], limits: Limits) -> Outcome {
    let e = engine().unwrap();
    let m = Module::new(&e, wasm).unwrap();
    run(&e, &m, "incr", 1, limits).outcome
}

#[test]
fn answers_in_protocol() {
    assert_eq!(go(&cell("", "", "= 2 2"), Limits::default()), Outcome::Ok { result: 2, state: 2 });
    assert_eq!(go(&cell("", "", "ops incr,get"), Limits::default()), Outcome::Ops { ops: vec!["incr".into(), "get".into()] });
}

#[test]
fn network_import_traps_with_its_name() {
    let w = cell(
        r#"(import "t0" "net_connect" (func $c (param i32 i32) (result i32)))"#,
        "(drop (call $c (i32.const 64) (i32.const 3)))",
        "= 1 1",
    );
    let Outcome::Trap { trap } = go(&w, Limits::default()) else { panic!("expected trap") };
    assert!(trap.contains("network call t0::net_connect denied"), "{trap}");
}

#[test]
fn wasi_socket_call_traps() {
    let w = cell(
        r#"(import "wasi_snapshot_preview1" "sock_accept" (func $a (param i32 i32 i32) (result i32)))"#,
        "(drop (call $a (i32.const 3) (i32.const 0) (i32.const 0)))",
        "= 1 1",
    );
    let Outcome::Trap { trap } = go(&w, Limits::default()) else { panic!("expected trap") };
    assert!(trap.contains("network call wasi_snapshot_preview1::sock_accept denied"), "{trap}");
}

#[test]
fn endless_loop_runs_out_of_fuel() {
    let w = cell("", "(loop $l (br $l))", "= 1 1");
    let Outcome::Trap { trap } = go(&w, Limits { fuel: 5_000_000, ..Default::default() }) else { panic!() };
    assert!(trap.contains("out of fuel"), "{trap}");
}

#[test]
fn endless_loop_hits_deadline_when_fuel_is_large() {
    let w = cell("", "(loop $l (br $l))", "= 1 1");
    let Outcome::Trap { trap } = go(&w, Limits { fuel: u64::MAX / 2, deadline_ms: 200, ..Default::default() }) else { panic!() };
    assert!(trap.contains("deadline of 200 ms"), "{trap}");
}

#[test]
fn memory_growth_past_cap_traps() {
    let w = cell("", "(drop (memory.grow (i32.const 1000)))", "= 1 1");
    let Outcome::Trap { trap } = go(&w, Limits { mem_mb: 8, ..Default::default() }) else { panic!() };
    assert!(trap.contains("memory cap of 8 MB"), "{trap}");
}
