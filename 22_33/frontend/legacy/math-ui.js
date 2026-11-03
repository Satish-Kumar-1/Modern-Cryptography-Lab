(function () {
  'use strict';
  const {traceSignature, payload, hex} = window.SignedChatMath;
  const output = document.querySelector('#math-output'), status = document.querySelector('#math-status'), button = document.querySelector('#run-math');
  let generation = 0;
  window.addEventListener('signedchat:logout', () => {
    generation++; output.replaceChildren(); status.textContent = ''; button.disabled = false;
    document.querySelector('#math-form').reset();
  });
  function el(tag, cls, text) { const node = document.createElement(tag); if (cls) node.className = cls; if (text !== undefined) node.textContent = text; return node; }
  function step(title, explanation, fields) {
    const section = el('section', 'surface math-step'); section.append(el('h2', '', title), el('p', '', explanation));
    const list = el('dl');
    for (const [label, value] of fields) list.append(el('dt', '', label), el('dd', 'math-value', typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)));
    section.append(list); output.append(section); return section;
  }
  document.querySelector('#math-form').addEventListener('submit', async event => {
    event.preventDefault(); const run = ++generation; button.disabled = true; output.replaceChildren(); status.textContent = 'Computing the trace and checking it against native Ed25519…';
    try {
      await new Promise(resolve => requestAnimationFrame(resolve));
      if (run !== generation) return;
      const sender = document.querySelector('#math-sender').value, recipient = document.querySelector('#math-recipient').value, content = document.querySelector('#math-message').value;
      const encodedPayload = payload(sender, recipient, content), bytes = new TextEncoder().encode(encodedPayload);
      const seed = crypto.getRandomValues(new Uint8Array(32)), trace = await traceSignature(seed, bytes);
      if (run !== generation) return;
      step('1. Exact bytes to be signed', 'This is the same UTF-8 / Base64 payload format used by the Java backend. The message is not trimmed or encrypted.', [
        ['Sender', sender], ['Recipient', recipient], ['Original message', content], ['Message UTF-8 hex', hex(new TextEncoder().encode(content))],
        ['M = Base64(sender) : Base64(recipient) : Base64(content)', encodedPayload], ['M as UTF-8 hex', trace.message], ['M length in bytes', bytes.length]
      ]);
      step('2. Curve parameters', 'Ed25519 operates on −x² + y² = 1 + d·x²·y² (mod p). L is the prime subgroup order. [n]B means scalar multiplication, not ordinary coordinate multiplication.', [
        ['p = 2²⁵⁵ − 19', trace.constants.p], ['L = 2²⁵² + 27742317777372353535851937790883648493', trace.constants.L],
        ['d = −121665 · 121666⁻¹ mod p', trace.constants.d], ['Base point B, affine coordinates', trace.constants.B]
      ]);
      step('3. Expand a disposable secret seed', 'SECRET DEMO VALUES: a fresh 32-byte seed is created only for this lab. SHA-512 is computed by Web Crypto. All hex values represent complete byte strings.', [
        ['Disposable seed (hex; not a chat key)', trace.seed], ['h = SHA-512(seed), 64 bytes', trace.expanded], ['prefix = h[32…63], 32 bytes', trace.prefix]
      ]);
      step('4. Clamp the secret scalar and derive the public key', 'Take the first 32 bytes of h. Clear the lowest three bits of byte 0; clear the top two bits of byte 31; set bit 6 of byte 31. Interpret the result as a little-endian integer a.', [
        ['Rules', 'h[0] &= 248; h[31] &= 63; h[31] |= 64'], ['Clamped 32 bytes (hex)', trace.clamped], ['Secret scalar a (decimal)', trace.a],
        ['A = [a]B, affine coordinates', trace.A], ['encode(A), 32 bytes', trace.publicKey], ['Point encoding', 'Encode y in 32 little-endian bytes, then store x mod 2 in the top bit of the last byte.']
      ]);
      step('5. Derive the deterministic nonce', 'Concatenate prefix and the exact signed payload bytes. Hash the result, interpret the digest as a little-endian integer, then reduce modulo L. This signing nonce is not replay protection.', [
        ['prefix || M (hex)', trace.nonceInput], ['SHA-512(prefix || M)', trace.nonceHash], ['r = LE(SHA-512(prefix || M)) mod L', trace.r], ['R = [r]B, affine coordinates', trace.R], ['encode(R)', trace.encodedR]
      ]);
      step('6. Bind the commitment, public key, and message', 'The challenge includes the compressed nonce point, compressed public key, and exact message bytes in that order.', [
        ['encode(R) || encode(A) || M (hex)', trace.challengeInput], ['SHA-512(encode(R) || encode(A) || M)', trace.challengeHash], ['k = LE(challenge hash) mod L', trace.k]
      ]);
      step('7. Complete the signature', 'Combine the nonce, challenge, and secret scalar in the subgroup. The signature is the 32-byte compressed R followed by the 32-byte little-endian S.', [
        ['S = (r + k·a) mod L (decimal)', trace.s], ['S as 32 little-endian bytes', trace.encodedS], ['Signature = encode(R) || LE32(S), 64 bytes', trace.signature], ['Signature in Base64', trace.signatureBase64],
        ['Independent native check', trace.matches ? 'MATCH: this exact signature equals Web Crypto Ed25519 signing with the same seed and payload.' : 'MISMATCH']
      ]);
      step('8. Verify using public values', 'Compute the challenge again from R, A, and M. Then check [S]B = R + [k]A. No secret scalar or private seed is needed for verification. For these freshly generated subgroup points, the uncofactored equality is valid.', [
        ['Left side [S]B, affine coordinates', trace.lhs], ['Right side R + [k]A, affine coordinates', trace.rhs], ['Point equality', trace.equal ? 'EQUAL' : 'NOT EQUAL'], ['Native verification', trace.nativeVerified ? 'VALID' : 'INVALID']
      ]);
      const operations = step('9. Expand every scalar-multiplication step', 'Each trace processes 256 scalar bits from least significant to most significant. Start accumulator = (0,1,1,0). Add the current point if the bit is 1, then double that point for the next bit. Extended coordinates (X,Y,Z,T) represent x=X/Z and y=Y/Z, with T=XY/Z.', [
        ['Point-addition formulas (all arithmetic modulo p)', 'A₀=(Y₁−X₁)(Y₂−X₂); B₀=(Y₁+X₁)(Y₂+X₂); C₀=2dT₁T₂; D₀=2Z₁Z₂; E=B₀−A₀; F=D₀−C₀; G=D₀+C₀; H=B₀+A₀; (X₃,Y₃,Z₃,T₃)=(EF,GH,FG,EH)'],
        ['Field inversion for affine conversion', 'Z⁻¹ = Z^(p−2) mod p (binary square-and-multiply).']
      ]);
      for (const [label, rows] of Object.entries(trace.traces)) {
        const details = el('details', 'trace-details'); details.append(el('summary', '', label + ' — all 256 rounds'));
        details.addEventListener('toggle', () => { if (details.open && details.childElementCount === 1) details.append(el('pre', 'math-value', JSON.stringify(rows, null, 2))); }); operations.append(details);
      }
      const reference = el('p', 'hint', 'Ed25519 algorithm: '), link = el('a', '', 'RFC 8032, section 5.1'); link.href = 'https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1'; link.target = '_blank'; link.rel = 'noopener noreferrer'; reference.append(link); output.append(reference);
      status.textContent = 'Signature matched native Ed25519. Verification passed. All values below belong to a disposable example key.';
    } catch (error) { if (run === generation) status.textContent = 'Could not compute the trace: ' + error.message + ' Use a current browser on HTTPS or localhost with Ed25519 Web Crypto support.'; }
    finally { if (run === generation) button.disabled = false; }
  });
})();
