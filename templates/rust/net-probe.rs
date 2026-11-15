// A counter that also tries to open a network connection on "ping".
// T0 cells have no network: Deploy works, and calling ping is stopped by a T0 trap.
mod t0;

fn handle(op: &str, count: &mut i64) -> Result<i64, String> {
    match op {
        "incr" => { *count += 1; Ok(*count) }
        "ping" => Ok(t0::net::connect("example.com:80") as i64),
        _ => Err(format!("unknown op {op}")),
    }
}

fn main() {
    t0::serve(&["incr", "ping"], handle);
}
