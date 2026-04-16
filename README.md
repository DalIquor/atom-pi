# ATOM‑PI
Deterministic, Transparent, Zero‑Magic Primitives for Symmetric Cryptography
Atom‑PI is a cryptographic substrate — a minimal set of invariant, explicit, fully‑visible operations from which modern symmetric algorithms can be constructed.

It is not a crypto library.
It does not implement SHA‑256, AES, ChaCha, PBKDF2, or any named primitive.

Instead, Atom‑PI exposes the atoms those algorithms are built from:

## ARX operations (Add‑Rotate‑Xor)

 - Boolean S‑boxes

 - Byte‑level S‑boxes

 - Linear diffusion operators

 - GF(2⁸) and GF(2¹²⁸) arithmetic

 - Structural combinators (compression, expansion, feedback)

 - Deterministic memory models

Everything else — SHA‑256, AES, ChaCha20, GHASH, HMAC, PBKDF2 — is a wrapper that composes these atoms and nothing else.

# Atom‑PI exists for one reason:

No convenience. Only competence.
Every transformation explicit.
Every state transition visible.
No magic. No helpers. No ghosts.

## Why Atom‑PI Exists
Most crypto code hides the real computation behind:

 - WebCrypto

 - JSON stringify

 - Unicode normalization

 - implicit endian conversions

 - nondeterministic Array.sort()

 - hidden memory allocations

 - “helpful” abstractions

 - silent type coercions

Atom‑PI rejects all of that.

It gives you the bare metal of symmetric cryptography — the exact atoms used in real designs — with no hidden behavior and no surprises.

If something changes state, you see it.
If something mixes bits, you see it.
If something allocates memory, you see it.

This makes Atom‑PI ideal for:

 - educational cryptography

 - verifiable implementations

 - deterministic pipelines

 - reproducible research

 - custom cipher/hash design

 - debugging and introspection

 - building “GOOD vs BAD” transparency demos

## Design Principles

1. Determinism

Every atom is pure.

No randomness. No hidden state. No side effects.

2. Transparency

Every transformation is explicit.

No helpers. No shortcuts. No magic.

3. Invariant Boundaries

All atoms enforce:

 - 32‑bit word invariants

 - 8‑bit byte invariants

 - fixed‑size state invariants

 - explicit handovers between stages

4. Composability

Atoms are small, orthogonal, and predictable.

Complex primitives are built by composing them.

5. Zero Trust

Nothing is assumed.
Nothing is implicit.
Nothing is “done for you.”

## What Atom‑PI Provides

### Arithmetic / Bit Atoms

 - wadd(a, b) — 32‑bit modular addition

 - wxor(a, b) — 32‑bit XOR

 - wrot(x, n) — 32‑bit rotate‑left

 - wshr(x, n) — logical right shift

These form the backbone of ARX designs (SHA‑256, ChaCha, Blake).

### Nonlinear Atoms

 - sbox_boolean(a, b, c, "ch" | "maj")

 - sbox_byte(x, table)

 - Boolean S‑boxes (SHA‑256) and byte S‑boxes (AES).

These are the only sources of cryptographic nonlinearity.

### Linear‑Mixing Atoms

 - lmix_word(w0, w1, w2, w3)

 - lmix_perm(state, perm)

 - lmix_gf256(column)

 - lmix_quarterround(a, b, c, d)

 - gf_mul(a128, b128)

These provide diffusion: spreading differences across the state.

### Structural Atoms

 - compress(state, block, round_fn, rounds)

 - expand(message, schedule_fn, count)

 - feedback(state, next)

 - feedback_indexed(state, memory, index)

These define how state evolves over time — the skeleton of hash/cipher designs.

### Memory Atoms

 - state_small(n) — fixed‑size word state

 - state_large(n) — large memory region for memory‑hard functions

## What Atom‑PI Does Not Do

Atom‑PI does not:

 - hash anything

 - encrypt anything

 - generate keys

 - provide random numbers

 - implement AES, SHA‑256, ChaCha, GHASH, PBKDF2, scrypt, Argon2

 - normalize strings

 - pad messages

 - allocate buffers for you

 - hide any computation

If you see “sha256” or “aes” inside Atom‑PI, something is wrong.

### Example: Building SHA‑256 (Wrapper)

A SHA‑256 implementation built on Atom‑PI would:

Use expand() to build the message schedule

Use compress() with a round function composed of:

 - wadd, wxor, wrot, wshr

 - sbox_boolean("ch"), sbox_boolean("maj")

Use feedback() for Merkle–Damgård chaining

Atom‑PI never performs these steps itself — it only provides the atoms.

### Example: Building AES (Wrapper)

AES would be built from:

 - sbox_byte()

 - lmix_perm()

 - lmix_gf256()

 - expand() for round keys

 - state_small(4) for 128‑bit blocks

Again: Atom‑PI does not implement AES.

It only provides the atoms AES is made from.

## Philosophy Summary

Atom‑PI is not a crypto library.

It is a crypto substrate.

It gives you:

 - the atoms

 - the invariants

 - the determinism

 - the transparency

You bring:

 - the structure

 - the round functions

 - the padding

 - the chaining

 - the algorithm

This separation is intentional.

It forces correctness, clarity, and competence.

## License

MIT — do whatever you want, but don’t blame Atom‑PI if you misuse it.

## Status

Stable substrate.

Wrapper (sha256.js) lives in a separate file.

## Author

SAL