function strToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    out.push(str.charCodeAt(i) & 0xff);
  }
  return out;
}

function runFull() {
  const msg = document.getElementById("msg").value;
  const bytes = strToBytes(msg);

  const H = sha256_bytes(bytes, AtomPI);
  console.log(H.length, H);
  const hex = sha256_hex(H);
  console.log("HEX:", hex, "LEN:", hex.length);

  const out = document.getElementById("out");
  out.innerHTML = "";      // remove any stray DOM nodes
  out.textContent = hex;   // write clean digest
}
