// sha256_block.js
// ============================================================
// SHA‑256 block processor (512‑bit chunks)
// ============================================================
//
// This file does NOT implement SHA‑256.
// It does NOT define constants, schedules, or rounds.
//
// It ONLY:
//   - pads a byte array
//   - splits it into 512‑bit blocks
//   - converts each block to 16×32‑bit words
//   - calls sha256_block(words, AtomPI) for each block
//
// The actual SHA‑256 compression logic lives in sha256.js.
// ============================================================

/**
 * sha256_block(words, AtomPI)
 *
 * This is the compression wrapper from sha256.js.
 * We import it here so we can call it per block.
 */
const sha256_block = window.sha256;

// ------------------------------------------------------------
// BYTE → WORDS HELPERS
// ------------------------------------------------------------

function bytes_to_words_be(bytes) {
  const words = [];
  for (let i = 0; i < bytes.length; i += 4) {
    const b0 = bytes[i]     || 0;
    const b1 = bytes[i + 1] || 0;
    const b2 = bytes[i + 2] || 0;
    const b3 = bytes[i + 3] || 0;
    const w = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
    words.push(w);
  }
  return words;
}

// ------------------------------------------------------------
// SHA‑256 PADDING
// ------------------------------------------------------------

function sha256_pad(bytes) {
  const out = bytes.slice();
  const bitLen = (out.length * 8) >>> 0;

  out.push(0x80);

  while ((out.length % 64) !== 56) {
    out.push(0x00);
  }

  const high = 0x00000000;
  const low  = bitLen >>> 0;

  out.push((high >>> 24) & 0xff);
  out.push((high >>> 16) & 0xff);
  out.push((high >>> 8)  & 0xff);
  out.push((high >>> 0)  & 0xff);

  out.push((low >>> 24) & 0xff);
  out.push((low >>> 16) & 0xff);
  out.push((low >>> 8)  & 0xff);
  out.push((low >>> 0)  & 0xff);

  return out;
}

// ------------------------------------------------------------
// HIGH‑LEVEL SHA‑256 (bytes → final state)
// ------------------------------------------------------------

function sha256_bytes(bytes, AtomPI) {
  const padded = sha256_pad(bytes);

  let H = null;

  for (let offset = 0; offset < padded.length; offset += 64) {
    const chunk = padded.slice(offset, offset + 64);
    const words = bytes_to_words_be(chunk); // 16 words

    // Call the existing SHA‑256 block wrapper
    H = sha256_block(words, AtomPI);
  }

  return H; // final 8-word state
}

// ------------------------------------------------------------
// BROWSER EXPORT
// ------------------------------------------------------------

if (typeof window !== "undefined") {
  window.sha256_bytes = sha256_bytes;
}