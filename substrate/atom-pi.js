// atom-pi.js
// ============================================================
// ATOM-PI: invariant primitives for symmetric cryptography
// ============================================================
//
// This file exposes the minimal set of "atoms" that modern
// symmetric crypto is built from.
//
// It does NOT implement:
//   - SHA-256
//   - AES
//   - ChaCha
//   - Blake
//   - PBKDF2
//   - scrypt
//   - any named "crypto function"
//
// It ONLY exposes:
//   - nonlinear atoms
//   - linear-mixing atoms
//   - arithmetic / bit atoms
//   - structural atoms
//   - memory atoms
//
// Everything else (sha256.js, aes.js, etc.) is a wrapper that
// composes these atoms and nothing else.
//
// Provenance rule:
//   Every transformation is explicit.
//   Every state transition is visible.
//   No magic helpers, no hidden dependencies.
// ============================================================

const AtomPI = {};

// ------------------------------------------------------------
// INTERNAL HELPERS (pure, small, no magic)
// ------------------------------------------------------------

/**
 * [handover] word32 → word32
 *   invariant_ok=true
 *   domain: 32-bit unsigned integers
 *
 * Ensures a JS number is treated as a 32-bit unsigned word.
 * All arithmetic / bit operations in AtomPI assume values
 * have been normalized through this at boundaries.
 */
function word32(x) {
  return x >>> 0;
}

/**
 * [handover] byte → byte
 *   invariant_ok=true
 *   domain: 0..255
 *
 * Ensures a JS number is treated as an 8-bit unsigned byte.
 */
function byte(x) {
  return x & 0xff;
}

// ============================================================
// ARITHMETIC / BIT OPS
// ============================================================
//
// These are the basic word-level operations used in ARX designs
// (Add-Rotate-Xor) and in hash/cipher round functions.
//
// They are NOT crypto by themselves.
// They are the glue that combines state in structured ways.
// ============================================================

/**
 * wadd(a, b)
 * [handover] word32 × word32 → word32
 *   invariant_ok=true
 *   domain: 32-bit unsigned integers
 *
 * Modular addition on 32-bit words.
 *
 * Nonlinear over GF(2), linear over integers.
 * Used in: SHA-256, ChaCha, many ARX designs.
 *
 * Provenance:
 *   - No carries leak outside 32 bits.
 *   - All callers must treat result as word32().
 */
function wadd(a, b) {
  const r = (a + b) >>> 0;
  return word32(r);
}

/**
 * wxor(a, b)
 * [handover] word32 × word32 → word32
 *   invariant_ok=true
 *   domain: 32-bit unsigned integers
 *
 * Bitwise XOR on 32-bit words.
 *
 * Linear over GF(2).
 * Used everywhere as the universal mixing operation.
 */
function wxor(a, b) {
  const r = (a ^ b) >>> 0;
  return word32(r);
}

/**
 * wrot(x, n)
 * [handover] word32 × int → word32
 *   invariant_ok=true
 *   domain: 32-bit unsigned integers, 0 ≤ n < 32
 *
 * Bitwise rotation (circular shift) left by n bits.
 *
 * Pure diffusion, no nonlinearity.
 * Critical in ARX designs (ChaCha, SHA-256).
 */
function wrot(x, n) {
  n = n & 31;
  const r = ((x << n) | (x >>> (32 - n))) >>> 0;
  return word32(r);
}

/**
 * wshr(x, n)
 * [handover] word32 × int → word32
 *   invariant_ok=true
 *   domain: 32-bit unsigned integers, 0 ≤ n < 32
 *
 * Logical right shift by n bits.
 *
 * Used in hash functions (e.g., SHA-256's Σ and σ functions)
 * as part of linear mixing.
 */
function wshr(x, n) {
  n = n & 31;
  const r = x >>> n;
  return word32(r);
}

// Expose arithmetic / bit ops
AtomPI.wadd = wadd;
AtomPI.wxor = wxor;
AtomPI.wrot = wrot;
AtomPI.wshr = wshr;

// ============================================================
// NONLINEAR ATOMS
// ============================================================
//
// These are the ONLY sources of cryptographic hardness in
// mainstream symmetric crypto.
//
// Everything else (linear mixing, rotations, XOR, addition)
// is linear or affine over some field.
//
// Without these, you only have diffusion, not confusion.
// ============================================================

/**
 * sbox_boolean(a, b, c, mode)
 * [handover] word32 × word32 × word32 → word32
 *   invariant_ok=true
 *   domain: 32-bit words
 *
 * Boolean S-box over words.
 *
 * This models functions like:
 *   - Ch(x, y, z)  = (x & y) ^ (~x & z)
 *   - Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
 *
 * These are used in SHA-256 and similar designs.
 *
 * mode:
 *   "ch"  → choose
 *   "maj" → majority
 *
 * Wrappers (e.g., sha256.js) will call this with fixed modes.
 */
function sbox_boolean(a, b, c, mode) {
  a = word32(a);
  b = word32(b);
  c = word32(c);

  let r;
  if (mode === "ch") {
    // Ch(a, b, c) = (a & b) ^ (~a & c)
    r = (a & b) ^ (~a & c);
  } else if (mode === "maj") {
    // Maj(a, b, c) = (a & b) ^ (a & c) ^ (b & c)
    r = (a & b) ^ (a & c) ^ (b & c);
  } else {
    throw new Error("sbox_boolean: unknown mode '" + mode + "'");
  }

  return word32(r);
}

/**
 * sbox_byte(x, table)
 * [handover] byte → byte
 *   invariant_ok=true
 *   domain: 0..255
 *
 * Byte-level S-box.
 *
 * This models AES-style S-boxes: a nonlinear substitution
 * over GF(2⁸) with high algebraic degree.
 *
 * table:
 *   An array[256] mapping input byte → output byte.
 *
 * Wrappers (e.g., aes.js) will provide the concrete table.
 */
function sbox_byte(x, table) {
  const b = byte(x);
  const out = table[b];
  if (out === undefined) {
    throw new Error("sbox_byte: table missing entry for " + b);
  }
  return byte(out);
}

// Expose nonlinear atoms
AtomPI.sbox_boolean = sbox_boolean;
AtomPI.sbox_byte = sbox_byte;

// ============================================================
// LINEAR-MIXING ATOMS
// ============================================================
//
// These atoms provide diffusion: they spread differences across
// bits, bytes, and words. Alone they are linear/affine, but when
// combined with nonlinear atoms they create avalanche.
// ============================================================

/**
 * lmix_word(w0, w1, w2, w3)
 * [handover] word32⁴ → word32
 *   invariant_ok=true
 *
 * Generic word-level linear recurrence / schedule step.
 *
 * This models things like SHA-256's message schedule:
 *   W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
 *
 * Here we keep it simple and generic:
 *   out = w0 ^ w1 ^ w2 ^ w3
 *
 * Wrappers can build richer schedules by composing wadd/wrot/wshr.
 */
function lmix_word(w0, w1, w2, w3) {
  w0 = word32(w0);
  w1 = word32(w1);
  w2 = word32(w2);
  w3 = word32(w3);
  const r = w0 ^ w1 ^ w2 ^ w3;
  return word32(r);
}

/**
 * lmix_perm(state, perm)
 * [handover] word32[] × int[] → word32[]
 *   invariant_ok=true
 *
 * Pure permutation of words.
 *
 * This models things like AES ShiftRows, or any fixed permutation
 * of state words/bytes.
 *
 * state:
 *   Array of words.
 * perm:
 *   Array of indices, same length as state.
 */
function lmix_perm(state, perm) {
  if (perm.length !== state.length) {
    throw new Error("lmix_perm: perm/state length mismatch");
  }

  const out = new Array(state.length);
  for (let i = 0; i < state.length; i++) {
    const idx = perm[i];
    out[i] = word32(state[idx] >>> 0);
  }
  return out;
}

// ---- GF(2^8) helpers for AES-style mixing ------------------

/**
 * gf256_mul(a, b)
 * [handover] byte × byte → byte
 *   invariant_ok=true
 *
 * Multiplication in GF(2⁸) with AES's irreducible polynomial
 *   x⁸ + x⁴ + x³ + x + 1  (0x11b)
 *
 * Used in AES MixColumns.
 */
function gf256_mul(a, b) {
  a = byte(a);
  b = byte(b);
  let res = 0;
  let x = a;
  let y = b;
  for (let i = 0; i < 8; i++) {
    if (y & 1) res ^= x;
    const hi = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi) x ^= 0x1b;
    y >>>= 1;
  }
  return byte(res);
}

/**
 * lmix_gf256(column)
 * [handover] byte[4] → byte[4]
 *   invariant_ok=true
 *
 * AES-style MixColumns on a single 4-byte column.
 *
 * This is a linear transform in GF(2⁸) with strong diffusion.
 *
 * column:
 *   Array[4] of bytes.
 */
function lmix_gf256(column) {
  if (column.length !== 4) {
    throw new Error("lmix_gf256: expected 4-byte column");
  }
  const a0 = byte(column[0]);
  const a1 = byte(column[1]);
  const a2 = byte(column[2]);
  const a3 = byte(column[3]);

  const r0 = gf256_mul(2, a0) ^ gf256_mul(3, a1) ^ a2 ^ a3;
  const r1 = a0 ^ gf256_mul(2, a1) ^ gf256_mul(3, a2) ^ a3;
  const r2 = a0 ^ a1 ^ gf256_mul(2, a2) ^ gf256_mul(3, a3);
  const r3 = gf256_mul(3, a0) ^ a1 ^ a2 ^ gf256_mul(2, a3);

  return [byte(r0), byte(r1), byte(r2), byte(r3)];
}

/**
 * lmix_quarterround(a, b, c, d)
 * [handover] word32⁴ → [word32, word32, word32, word32]
 *   invariant_ok=true
 *
 * ChaCha/Salsa-style quarter-round.
 *
 * This is a linear structure over the ARX atoms:
 *   a += b; d ^= a; d <<< 16;
 *   c += d; b ^= c; b <<< 12;
 *   a += b; d ^= a; d <<< 8;
 *   c += d; b ^= c; b <<< 7;
 *
 * Wrappers (e.g., chacha.js) will arrange these over a 16-word state.
 */
function lmix_quarterround(a, b, c, d) {
  a = word32(a);
  b = word32(b);
  c = word32(c);
  d = word32(d);

  a = wadd(a, b);
  d = wxor(d, a);
  d = wrot(d, 16);

  c = wadd(c, d);
  b = wxor(b, c);
  b = wrot(b, 12);

  a = wadd(a, b);
  d = wxor(d, a);
  d = wrot(d, 8);

  c = wadd(c, d);
  b = wxor(b, c);
  b = wrot(b, 7);

  return [a, b, c, d];
}

/**
 * gf_mul(a, b)
 * [handover] [word32×4] × [word32×4] → [word32×4]
 *   invariant_ok=true
 *
 * Multiplication in GF(2¹²⁸) for GHASH-style constructions.
 *
 * Representation:
 *   128-bit value as [w0, w1, w2, w3], big-endian:
 *     w0 = most significant 32 bits
 *     w3 = least significant 32 bits
 *
 * This is a straightforward shift-and-xor implementation.
 * It is not optimized; it is a reference atom.
 */
function gf_mul(a, b) {
  if (a.length !== 4 || b.length !== 4) {
    throw new Error("gf_mul: expected [4-word] inputs");
  }

  // Clone inputs as 128-bit values in two arrays.
  let x = [word32(a[0]), word32(a[1]), word32(a[2]), word32(a[3])];
  let y = [word32(b[0]), word32(b[1]), word32(b[2]), word32(b[3])];

  // Result starts at 0.
  let z = [0, 0, 0, 0];

  // Polynomial: x^128 + x^7 + x^2 + x + 1 (0xe1000000000000000000000000000000)
  const R = [0xe1000000, 0x00000000, 0x00000000, 0x00000000];

  for (let i = 0; i < 128; i++) {
    // If LSB of y is 1, z ^= x
    const lsb = y[3] & 1;
    if (lsb) {
      z[0] ^= x[0];
      z[1] ^= x[1];
      z[2] ^= x[2];
      z[3] ^= x[3];
    }

    // y >>= 1
    const y0 = y[0];
    const y1 = y[1];
    const y2 = y[2];
    const y3 = y[3];
    y[3] = (y3 >>> 1) | ((y2 & 1) << 31);
    y[2] = (y2 >>> 1) | ((y1 & 1) << 31);
    y[1] = (y1 >>> 1) | ((y0 & 1) << 31);
    y[0] = (y0 >>> 1);

    // Track MSB of x before shift
    const msb = x[0] & 0x80000000;

    // x <<= 1
    const x0 = x[0];
    const x1 = x[1];
    const x2 = x[2];
    const x3 = x[3];
    x[0] = ((x0 << 1) | (x1 >>> 31)) >>> 0;
    x[1] = ((x1 << 1) | (x2 >>> 31)) >>> 0;
    x[2] = ((x2 << 1) | (x3 >>> 31)) >>> 0;
    x[3] = (x3 << 1) >>> 0;

    // If msb was set, reduce with R
    if (msb) {
      x[0] ^= R[0];
      x[1] ^= R[1];
      x[2] ^= R[2];
      x[3] ^= R[3];
    }
  }

  return [word32(z[0]), word32(z[1]), word32(z[2]), word32(z[3])];
}

// Expose linear-mixing atoms
AtomPI.lmix_word = lmix_word;
AtomPI.lmix_perm = lmix_perm;
AtomPI.lmix_gf256 = lmix_gf256;
AtomPI.lmix_quarterround = lmix_quarterround;
AtomPI.gf_mul = gf_mul;

// ============================================================
// STRUCTURAL ATOMS
// ============================================================
//
// These atoms define how state evolves over time.
// They do not fix any particular algorithm; they provide
// the skeleton that wrappers (sha256.js, aes.js, etc.) fill.
// ============================================================

/**
 * compress(state, block, round_fn, rounds)
 * [handover] state × block → state
 *   invariant_ok=true
 *
 * Generic hash-style compression function.
 *
 * This models cores like SHA-256's 64-round loop:
 *   for i in 0..63:
 *     state = ROUND(state, block, i)
 *
 * round_fn:
 *   function(state, block, roundIndex) → newState
 *
 * Wrappers define the concrete round function.
 */
function compress(state, block, round_fn, rounds) {
  if (typeof round_fn !== "function") {
    throw new Error("compress: round_fn must be a function");
  }
  if ((rounds | 0) <= 0) {
    throw new Error("compress: rounds must be > 0");
  }

  let s = state.slice(); // copy
  for (let i = 0; i < rounds; i++) {
    s = round_fn(s, block, i);
  }
  return s;
}

/**
 * expand(message, schedule_fn, count)
 * [handover] message → schedule[]
 *   invariant_ok=true
 *
 * Generic message/key schedule expansion.
 *
 * This models things like:
 *   - SHA-256 message schedule W[0..63]
 *   - AES round keys
 *
 * schedule_fn:
 *   function(message, index, schedule) → word32
 *
 * count:
 *   number of schedule entries to produce.
 */
function expand(message, schedule_fn, count) {
  if (typeof schedule_fn !== "function") {
    throw new Error("expand: schedule_fn must be a function");
  }
  if ((count | 0) <= 0) {
    throw new Error("expand: count must be > 0");
  }

  const schedule = new Array(count);
  for (let i = 0; i < count; i++) {
    schedule[i] = word32(schedule_fn(message, i, schedule));
  }
  return schedule;
}


/**
 * feedback(state, next)
 * [handover] state × state → state
 *   invariant_ok=true
 *
 * Generic chaining feedback.
 *
 * This models:
 *   - Merkle–Damgård chaining
 *   - HMAC inner→outer chaining
 *   - PRNG state updates
 *
 * Here we use XOR as the default feedback combiner.
 * Wrappers can layer additional structure on top.
 */
function feedback(state, next) {
  if (state.length !== next.length) {
    throw new Error("feedback: state length mismatch");
  }
  const out = new Array(state.length);
  for (let i = 0; i < state.length; i++) {
    out[i] = wxor(state[i], next[i]);
  }
  return out;
}

/**
 * feedback_indexed(state, memory, index)
 * [handover] state × memory × index → state
 *   invariant_ok=true
 *
 * Memory-hard feedback.
 *
 * This models constructions like scrypt's ROMix:
 *   - state is used as an index into a large memory array
 *   - the fetched block is mixed back into state
 *
 * Here we keep it generic:
 *   state' = state XOR memory[index]
 */
function feedback_indexed(state, memory, index) {
  const block = memory[index];
  if (!block || block.length !== state.length) {
    throw new Error("feedback_indexed: invalid memory block");
  }
  const out = new Array(state.length);
  for (let i = 0; i < state.length; i++) {
    out[i] = wxor(state[i], block[i]);
  }
  return out;
}

// Expose structural atoms
AtomPI.compress = compress;
AtomPI.expand = expand;
AtomPI.feedback = feedback;
AtomPI.feedback_indexed = feedback_indexed;

// ============================================================
// MEMORY ATOMS
// ============================================================
//
// Memory is not an operation; it's a structural parameter.
// But in practice, small vs large state behaves like an atom
// in the design space.
// ============================================================

/**
 * state_small(size)
 * [handover] int → word32[]
 *   invariant_ok=true
 *
 * Allocate a small fixed-size state.
 *
 * Used in:
 *   - AES (128-bit state)
 *   - SHA-256 (256-bit state)
 *   - HMAC, PRNGs, etc.
 */
function state_small(size) {
  const n = size | 0;
  if (n <= 0) throw new Error("state_small: size must be > 0");
  const s = new Array(n);
  for (let i = 0; i < n; i++) s[i] = 0 >>> 0;
  return s;
}

/**
 * state_large(size)
 * [handover] int → any[]
 *   invariant_ok=true
 *
 * Allocate a large memory region for memory-hard functions.
 *
 * Used in:
 *   - scrypt V array
 *   - Argon-like constructions (if wrapped)
 */
function state_large(size) {
  const n = size | 0;
  if (n <= 0) throw new Error("state_large: size must be > 0");
  const m = new Array(n);
  for (let i = 0; i < n; i++) m[i] = null;
  return m;
}

// Expose memory atoms
AtomPI.state_small = state_small;
AtomPI.state_large = state_large;

// ============================================================
// END OF ATOM-PI
// ============================================================
//
// This file is the bottom of the stack.
// All named crypto primitives must be built as wrappers that
// compose these atoms and nothing else.
//
// If you see "sha256" or "aes" in this file, something is wrong.
// ============================================================

// For environments that support modules:
if (typeof module !== "undefined" && module.exports) {
  module.exports = AtomPI;
}