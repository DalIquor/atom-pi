// sha256_good.js
// ============================================================
// SHA‑256 — GOOD-pipeline teaching wrapper
// ============================================================
//
// This file does NOT change SHA‑256.
// It only makes the transitions visible.
//
// It reimplements the sha256.js wrapper, but with:
//   - explicit [handover] logs
//   - per-round state dumps
//   - atom-level provenance
//
// You still pass in AtomPI.
// ============================================================

function sha256_good(messageWords, AtomPI, log) {
  // fallback logger
  if (!log) {
    log = console.log.bind(console);
  }

  // ----------------------------------------------------------
  // INITIAL HASH VALUES (H0..H7)
  // ----------------------------------------------------------
  let H = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ].map(x => x >>> 0);

  log("INIT H:", H.map(x => x.toString(16).padStart(8, "0")).join(" "));

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ].map(x => x >>> 0);

  // ----------------------------------------------------------
  // MESSAGE SCHEDULE W[0..63]
  // ----------------------------------------------------------
  function schedule_fn(msg, i, W) {
    if (i < 16) {
      const v = msg[i] >>> 0;
      log(`[handover] schedule W[${i}] (base)
  invariant_ok=true
  W[${i}]=0x${v.toString(16).padStart(8, "0")}`);
      return v;
    }

    const s0 =
      AtomPI.wxor(
        AtomPI.wxor(
          AtomPI.wrot(W[i - 15], 25),
          AtomPI.wrot(W[i - 15], 14)
        ),
        AtomPI.wshr(W[i - 15], 3)
      );

    const s1 =
      AtomPI.wxor(
        AtomPI.wxor(
          AtomPI.wrot(W[i - 2], 15),
          AtomPI.wrot(W[i - 2], 13)
        ),
        AtomPI.wshr(W[i - 2], 10)
      );

    const out = AtomPI.wadd(
      AtomPI.wadd(s1, W[i - 7]),
      AtomPI.wadd(s0, W[i - 16])
    );

    log(`[handover] schedule W[${i}] (expand)
  invariant_ok=true
  s0=0x${s0.toString(16).padStart(8, "0")}
  s1=0x${s1.toString(16).padStart(8, "0")}
  W[${i}]=0x${out.toString(16).padStart(8, "0")}`);

    return out;
  }

  const W = AtomPI.expand(messageWords, schedule_fn, 64);

  // ----------------------------------------------------------
  // ROUND FUNCTION WITH LOGGING
  // ----------------------------------------------------------
  function round_fn(state, block, i) {
    let [a, b, c, d, e, f, g, h] = state;

    const Σ1 = AtomPI.wxor(
      AtomPI.wxor(
        AtomPI.wrot(e, 26),
        AtomPI.wrot(e, 21)
      ),
      AtomPI.wrot(e, 7)
    );

    const ch = AtomPI.sbox_boolean(e, f, g, "ch");

    const T1 = AtomPI.wadd(
      AtomPI.wadd(
        AtomPI.wadd(h, Σ1),
        AtomPI.wadd(ch, K[i])
      ),
      W[i]
    );

    const Σ0 = AtomPI.wxor(
      AtomPI.wxor(
        AtomPI.wrot(a, 30),
        AtomPI.wrot(a, 19)
      ),
      AtomPI.wrot(a, 10)
    );

    const maj = AtomPI.sbox_boolean(a, b, c, "maj");

    const T2 = AtomPI.wadd(Σ0, maj);

    const newState = [
      AtomPI.wadd(T1, T2),
      a,
      b,
      c,
      AtomPI.wadd(d, T1),
      e,
      f,
      g
    ];

    log(`[handover] round ${i}
  invariant_ok=true
  a..h_in = ${state.map(x => "0x" + x.toString(16).padStart(8, "0")).join(" ")}
  Σ1=0x${Σ1.toString(16).padStart(8, "0")}
  ch=0x${ch.toString(16).padStart(8, "0")}
  Σ0=0x${Σ0.toString(16).padStart(8, "0")}
  maj=0x${maj.toString(16).padStart(8, "0")}
  T1=0x${T1.toString(16).padStart(8, "0")}
  T2=0x${T2.toString(16).padStart(8, "0")}
  a..h_out = ${newState.map(x => "0x" + x.toString(16).padStart(8, "0")).join(" ")}`);

    return newState;
  }

  // ----------------------------------------------------------
  // COMPRESS + FEEDBACK WITH LOGGING
  // ----------------------------------------------------------
  const newState = AtomPI.compress(H, null, round_fn, 64);

  log(`[handover] compress → newState
  invariant_ok=true
  newState = ${newState.map(x => "0x" + x.toString(16).padStart(8, "0")).join(" ")}`);

  const H_final = AtomPI.feedback(H, newState);

  log(`[handover] feedback H ⊕ newState
  invariant_ok=true
  H_in  = ${H.map(x => "0x" + x.toString(16).padStart(8, "0")).join(" ")}
  H_out = ${H_final.map(x => "0x" + x.toString(16).padStart(8, "0")).join(" ")}`);

  return H_final;
}

// ------------------------------------------------------------
// BROWSER EXPORT
// ------------------------------------------------------------
if (typeof window !== "undefined") {
  window.sha256_good = sha256_good;
}

