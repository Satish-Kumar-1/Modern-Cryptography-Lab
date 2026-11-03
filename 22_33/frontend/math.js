/* Educational Ed25519 arithmetic only. Chat signing remains Java JCA Ed25519.
 * Native Web Crypto signs/verifies each lab result independently. */
(function (global) {
  'use strict';
  const P = (1n << 255n) - 19n;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const mod = (a, p = P) => ((a % p) + p) % p;
  function pow(a, n) { let result = 1n; a = mod(a); while (n) { if (n & 1n) result = mod(result * a); a = mod(a * a); n >>= 1n; } return result; }
  const inverse = a => pow(a, P - 2n);
  const D = mod(-121665n * inverse(121666n));
  const B = [15112221349535400772501151409588531511454012693041857206046113283949847762202n,
    46316835694926478169428394003475163141307993866256225615783033603165251855960n, 1n];
  B.push(mod(B[0] * B[1]));
  function add(p, q) {
    const a = mod((p[1] - p[0]) * (q[1] - q[0])), b = mod((p[1] + p[0]) * (q[1] + q[0]));
    const c = mod(2n * D * p[3] * q[3]), d = mod(2n * p[2] * q[2]);
    const e = mod(b - a), f = mod(d - c), g = mod(d + c), h = mod(b + a);
    return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  }
  function multiply(n, point, includeTrace) {
    let accumulator = [0n, 1n, 1n, 0n], next = [...point]; const trace = [];
    for (let bit = 0; bit < 256; bit++) {
      const selected = Number((n >> BigInt(bit)) & 1n);
      if (selected) accumulator = add(accumulator, next);
      next = add(next, next);
      if (includeTrace) trace.push({ bit, selected, accumulator: accumulator.map(String), nextDouble: next.map(String) });
    }
    return { point: accumulator, trace };
  }
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  function fromHex(value) { if (!/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error('Invalid hex'); return Uint8Array.from(value.match(/../g) || [], b => parseInt(b, 16)); }
  function le(bytes) { let n = 0n; for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) + BigInt(bytes[i]); return n; }
  function le32(n) { const bytes = new Uint8Array(32); for (let i = 0; i < 32; i++) { bytes[i] = Number(n & 255n); n >>= 8n; } return bytes; }
  const concat = (...parts) => { const result = new Uint8Array(parts.reduce((n, part) => n + part.length, 0)); let offset = 0; for (const part of parts) { result.set(part, offset); offset += part.length; } return result; };
  function affine(point) { const inv = inverse(point[2]); return { x: mod(point[0] * inv).toString(), y: mod(point[1] * inv).toString() }; }
  function encode(point) { const xy = affine(point); const bytes = le32(BigInt(xy.y)); bytes[31] |= Number(BigInt(xy.x) & 1n) << 7; return bytes; }
  const hash = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-512', bytes));
  function base64(bytes) { let value = ''; for (const b of bytes) value += String.fromCharCode(b); return btoa(value); }
  function payload(sender, recipient, content) { const utf8 = new TextEncoder(); return `${base64(utf8.encode(sender))}:${base64(utf8.encode(recipient))}:${base64(utf8.encode(content))}`; }
  async function traceSignature(seed, message, includeTrace = true) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('An Ed25519 seed is exactly 32 bytes.');
    const expanded = await hash(seed), clamped = expanded.slice(0, 32), prefix = expanded.slice(32);
    clamped[0] &= 248; clamped[31] &= 63; clamped[31] |= 64;
    const a = le(clamped), publicCalculation = multiply(a, B, includeTrace), A = encode(publicCalculation.point);
    const nonceInput = concat(prefix, message), nonceHash = await hash(nonceInput), r = le(nonceHash) % L;
    const nonceCalculation = multiply(r, B, includeTrace), R = encode(nonceCalculation.point);
    const challengeInput = concat(R, A, message), challengeHash = await hash(challengeInput), k = le(challengeHash) % L;
    const s = mod(r + k * a, L), signature = concat(R, le32(s));
    const lhs = multiply(s, B, includeTrace), kA = multiply(k, publicCalculation.point, includeTrace), rhs = add(nonceCalculation.point, kA.point);
    const key = await crypto.subtle.importKey('pkcs8', concat(fromHex('302e020100300506032b657004220420'), seed), 'Ed25519', false, ['sign']);
    const nativeSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', key, message));
    const publicKey = await crypto.subtle.importKey('raw', A, 'Ed25519', false, ['verify']);
    const nativeVerified = await crypto.subtle.verify('Ed25519', publicKey, nativeSignature, message);
    const matches = hex(signature) === hex(nativeSignature);
    const equal = mod(lhs.point[0] * rhs[2] - rhs[0] * lhs.point[2]) === 0n && mod(lhs.point[1] * rhs[2] - rhs[1] * lhs.point[2]) === 0n;
    if (!matches || !equal || !nativeVerified) throw new Error('The educational trace did not match native Ed25519. No result was accepted.');
    return { seed: hex(seed), message: hex(message), expanded: hex(expanded), clamped: hex(clamped), prefix: hex(prefix), a: String(a),
      publicKey: hex(A), A: affine(publicCalculation.point), nonceInput: hex(nonceInput), nonceHash: hex(nonceHash), r: String(r),
      R: affine(nonceCalculation.point), encodedR: hex(R), challengeInput: hex(challengeInput), challengeHash: hex(challengeHash), k: String(k),
      s: String(s), encodedS: hex(le32(s)), signature: hex(signature), signatureBase64: base64(signature),
      lhs: affine(lhs.point), rhs: affine(rhs), matches, nativeVerified, equal,
      constants: { p: String(P), L: String(L), d: String(D), B: affine(B) },
      traces: { 'A = [a]B': publicCalculation.trace, 'R = [r]B': nonceCalculation.trace, '[S]B': lhs.trace, '[k]A': kA.trace } };
  }
  global.SignedChatMath = { traceSignature, payload, hex, fromHex };
})(globalThis);
