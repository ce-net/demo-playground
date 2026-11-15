//! The T0 SDK for Rust cells (fixed; its hash is part of every build descriptor).
//! A T0 cell reads `<op> <state>` on stdin and answers `= <result> <state>` or `! <error>`.

use std::io::{Read, Write};

/// Answer one call: `ops` are the op names this cell takes, `handle` runs one of them.
pub fn serve(ops: &[&str], handle: fn(&str, &mut i64) -> Result<i64, String>) {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let mut words = input.split_whitespace();
    let op = words.next().unwrap_or("");
    let mut state: i64 = words.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let out = if op == "__describe" {
        format!("ops {}", ops.join(","))
    } else if !ops.contains(&op) {
        format!("! unknown op {op}")
    } else {
        match handle(op, &mut state) {
            Ok(result) => format!("= {result} {state}"),
            Err(e) => format!("! {e}"),
        }
    };
    let _ = std::io::stdout().write_all(out.as_bytes());
}

/// Network access as a host on a higher tier would offer it. On T0 the call traps.
#[allow(dead_code)]
pub mod net {
    #[link(wasm_import_module = "t0")]
    extern "C" {
        fn net_connect(addr: *const u8, len: usize) -> i32;
    }
    pub fn connect(addr: &str) -> i32 {
        unsafe { net_connect(addr.as_ptr(), addr.len()) }
    }
}
