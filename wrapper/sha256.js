// sha256.js
// ============================================================
// SHA‑256 — ATOMIC DEPENDENCY GRAPH
// ============================================================
//
// sha256
//   └─ COMPRESS
//        ├─ sbox_boolean      (Ch, Maj)
//        ├─ lmix_word         (message schedule W[i])
//        ├─ wrot              (Σ0, Σ1, σ0, σ1)
//        ├─ wshr              (σ0, σ1)
//        ├─ wadd              (T1, T2 accumulation)
//        └─ wxor              (mixing)
//
// STATE:
//   state_small(8)     → 8 × 32‑bit words (a..h)
//   expand(...)        → W[0..63] schedule
//
// STRUCTURE:
//   64 rounds
//   Merkle–Damgård style FEEDBACK
//
// This file is a WRAPPER.
// It composes AtomPI atoms into the SHA‑256 hash function.
// ============================================================

function sha256(messageWords, AtomPI) {
  // ----------------------------------------------------------
  // INITIAL HASH VALUES (H0..H7)
  // ----------------------------------------------------------
  let H = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ].map(x => x >>> 0);

  // ----------------------------------------------------------
  // CONSTANTS K[0..63]
  // ----------------------------------------------------------
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
    if (i < 16) return msg[i] >>> 0;

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

    return AtomPI.wadd(
      AtomPI.wadd(s1, W[i - 7]),
      AtomPI.wadd(s0, W[i - 16])
    );
  }

  const W = AtomPI.expand(messageWords, schedule_fn, 64);

  // ----------------------------------------------------------
  // ROUND FUNCTION
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

    // Update state
    return [
      AtomPI.wadd(T1, T2),
      a,
      b,
      c,
      AtomPI.wadd(d, T1),
      e,
      f,
      g
    ];
  }

  // ----------------------------------------------------------
  // COMPRESS
  // ----------------------------------------------------------
  const newState = AtomPI.compress(H, null, round_fn, 64);

  // ----------------------------------------------------------
  // FEEDBACK (H = H XOR newState)
  // ----------------------------------------------------------
  H = H.map((h, i) => AtomPI.wadd(h, newState[i]));

  return H;
}

// Export for module environments
if (typeof module !== "undefined" && module.exports) {
  module.exports = sha256;
}

// Browser global
if (typeof window !== "undefined") {
  window.sha256 = sha256;
}
