// The T0 SDK for JavaScript cells (fixed; its hash is part of every build descriptor).
// A T0 cell reads `<op> <state>` on stdin and answers `= <result> <state>` or `! <error>`.
function serve(ops, handle) {
  const chunks = [];
  const buf = new Uint8Array(1024);
  for (;;) {
    const n = Javy.IO.readSync(0, buf);
    if (n <= 0) break;
    chunks.push(...buf.subarray(0, n));
  }
  const [op = "", s = "0"] = new TextDecoder().decode(new Uint8Array(chunks)).trim().split(/\s+/);
  const state = { count: Number.parseInt(s, 10) || 0 };
  let out;
  if (op === "__describe") out = "ops " + ops.join(",");
  else if (!ops.includes(op)) out = "! unknown op " + op;
  else {
    try {
      const result = handle(op, state);
      out = "= " + Math.trunc(Number(result)) + " " + Math.trunc(state.count);
    } catch (e) {
      out = "! " + String(e && e.message ? e.message : e);
    }
  }
  Javy.IO.writeSync(1, new TextEncoder().encode(out));
}
