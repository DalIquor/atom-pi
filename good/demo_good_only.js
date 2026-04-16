// demo_good_only.js
// ============================================================
// Minimal GOOD‑pipeline demo glue
// ============================================================

// Convert JS string → byte array
function strToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    out.push(str.charCodeAt(i) & 0xff);
  }
  return out;
}

// Convert first 64 bytes → 16 words (big‑endian)
function bytesToWordsFirstBlock(bytes) {
  const block = bytes.slice(0, 64);
  const words = [];
  for (let i = 0; i < 64; i += 4) {
    const b0 = block[i]     || 0;
    const b1 = block[i + 1] || 0;
    const b2 = block[i + 2] || 0;
    const b3 = block[i + 3] || 0;
    words.push(((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0);
  }
  return words;
}

function runGood() {
  const msg = document.getElementById("msg").value;
  const bytes = strToBytes(msg);

  // 1. Convert to 16 words (first block only)
  const words = bytesToWordsFirstBlock(bytes);

  // 2. Run GOOD‑pipeline SHA‑256
  let logOut = "";
  sha256_good(words, AtomPI, (line) => {
    logOut += line + "\n";
  });
  document.getElementById("log").textContent = logOut;

  // 3. Render dependency graph
  const deps = renderDependencyGraph({
    name: "sha256_good",
    atoms: [
      "wadd",
      "wxor",
      "wrot",
      "wshr",
      "sbox_boolean",
      "expand",
      "compress",
      "feedback"
    ]
  });
  document.getElementById("deps").textContent = deps;
}
