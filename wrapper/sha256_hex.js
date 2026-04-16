// sha256_hex.js
// ============================================================
// SHA‑256 hex encoder
// ============================================================
//
// This file does NOT:
//   - hash anything
//   - pad anything
//   - process blocks
//   - run compression
//
// It ONLY:
//   - takes the final 8-word SHA‑256 state
//   - converts it to a 64‑char hex string
//
// This is the final presentation layer.
// ============================================================

/**
 * word32_to_hex(w)
 * Convert a 32-bit word to 8 hex chars.
 */
function word32_to_hex(w) {
  return (
    ((w >>> 24) & 0xff).toString(16).padStart(2, "0") +
    ((w >>> 16) & 0xff).toString(16).padStart(2, "0") +
    ((w >>> 8)  & 0xff).toString(16).padStart(2, "0") +
    ((w >>> 0)  & 0xff).toString(16).padStart(2, "0")
  );
}

/**
 * sha256_hex(finalState)
 * [handover] [8 × word32] → hex string
 *
 * finalState:
 *   The 8-word output from sha256_bytes().
 */
function sha256_hex(finalState) {
  let out = "";
  for (let i = 0; i < finalState.length; i++) {
    out += word32_to_hex(finalState[i]);
  }
  return out;
}

// ------------------------------------------------------------
// well
// ------------------------------------------------------------
if (typeof window !== "undefined") {
  window.sha256_hex = sha256_hex;
}

