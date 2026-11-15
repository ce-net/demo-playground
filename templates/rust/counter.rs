// A counter cell. Change STEP, then press Deploy.
mod t0;

const STEP: i64 = 1;

fn handle(op: &str, count: &mut i64) -> Result<i64, String> {
    match op {
        "incr" => { *count += STEP; Ok(*count) }
        "get" => Ok(*count),
        "reset" => { *count = 0; Ok(0) }
        _ => Err(format!("unknown op {op}")),
    }
}

fn main() {
    t0::serve(&["incr", "get", "reset"], handle);
}
