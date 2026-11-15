// A cell that never stops on "spin". T0 meters every instruction: the call ends in an out-of-fuel trap.
function handle(op, s) {
  if (op === "spin") { for (;;) { s.count++; } }
  s.count += 1;
  return s.count;
}

serve(["incr", "spin"], handle);
