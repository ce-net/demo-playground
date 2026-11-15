// A counter cell. Change STEP, then press Deploy.
const STEP = 1;

function handle(op, s) {
  switch (op) {
    case "incr": s.count += STEP; return s.count;
    case "get": return s.count;
    case "reset": s.count = 0; return 0;
  }
  throw new Error("unknown op " + op);
}

serve(["incr", "get", "reset"], handle);
