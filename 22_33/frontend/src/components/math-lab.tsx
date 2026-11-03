import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { traceSignature, payload, hex } from "@/lib/math.js";
import type { SignatureTrace } from "@/lib/math.js";
import { errorMessage, useTask } from "@/lib/use-task";

function Step({
  title,
  description,
  fields,
}: {
  title: string;
  description: string;
  fields: [string, unknown][];
}) {
  return (
    <Card className="surface math-step">
      <h2>{title}</h2>
      <p>{description}</p>
      <dl>
        {fields.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd className="math-value">
              {typeof value === "object"
                ? JSON.stringify(value, null, 2)
                : String(value)}
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
function Rounds({ trace }: { trace: SignatureTrace }) {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  return (
    <>
      {Object.entries(trace.traces).map(([name, rows]) => (
        <details
          className="trace-details"
          key={name}
          onToggle={(event) =>
            setOpen((previous) => ({
              ...previous,
              [name]: event.currentTarget.open,
            }))
          }
        >
          <summary>{name} — all 256 rounds</summary>
          {open[name] && (
            <pre className="math-value">{JSON.stringify(rows, null, 2)}</pre>
          )}
        </details>
      ))}
    </>
  );
}
export function MathLab({
  initial,
}: {
  initial?: { sender: string; recipient: string; content: string };
}) {
  const [sender, setSender] = useState(initial?.sender || "Alice"),
    [recipient, setRecipient] = useState(initial?.recipient || "Bob");
  const [content, setContent] = useState(initial?.content || "Hello Bob!"),
    [trace, setTrace] = useState<SignatureTrace | null>(null),
    [status, setStatus] = useState("");
  const task = useTask();
  return (
    <section className="padded-view">
      <div className="section-intro">
        <h2>Follow the numbers.</h2>
        <p>
          Exact payload bytes, hashes, curve points, signature, and
          verification.
        </p>
      </div>
      <div className="surface">
        <p className="math-warning">
          Disposable example keys only. Their secret values are intentionally
          shown. Actual messaging uses Java cryptography.
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            setTrace(null);
            setStatus("Computing and checking against native Ed25519…");
            void task.run(
              async (current) => {
                const seed = crypto.getRandomValues(new Uint8Array(32)),
                  result = await traceSignature(
                    seed,
                    new TextEncoder().encode(
                      payload(sender, recipient, content),
                    ),
                  );
                if (current()) {
                  setTrace(result);
                  setStatus(
                    "Signature matched native Ed25519. Verification passed.",
                  );
                }
              },
              (error) => setStatus(errorMessage(error)),
            );
          }}
        >
          <div className="form-row">
            <label>
              Sender
              <Input
                value={sender}
                onChange={(event) => {
                  setSender(event.target.value);
                  setTrace(null);
                  setStatus("");
                }}
                required
                disabled={task.busy}
              />
            </label>
            <label>
              Recipient
              <Input
                value={recipient}
                onChange={(event) => {
                  setRecipient(event.target.value);
                  setTrace(null);
                  setStatus("");
                }}
                required
                disabled={task.busy}
              />
            </label>
          </div>
          <label>
            Message
            <Textarea
              rows={3}
              value={content}
              onChange={(event) => {
                setContent(event.target.value);
                setTrace(null);
                setStatus("");
              }}
              disabled={task.busy}
            />
          </label>
          <Button type="submit" disabled={task.busy}>
            Generate disposable key & show the math
          </Button>
          <p role="status">{status}</p>
        </form>
      </div>
      {trace && (
        <>
          <Step
            title="1. Exact bytes to be signed"
            description="The backend signs this same UTF-8/Base64 payload format. No trimming or encryption."
            fields={[
              ["Sender", sender],
              ["Recipient", recipient],
              ["Original message", content],
              ["Message UTF-8 hex", hex(new TextEncoder().encode(content))],
              [
                "M = Base64(sender) : Base64(recipient) : Base64(content)",
                payload(sender, recipient, content),
              ],
              ["M as UTF-8 hex", trace.message],
            ]}
          />
          <Step
            title="2. Curve parameters"
            description="Ed25519: −x² + y² = 1 + d·x²·y² (mod p). [n]B means scalar multiplication."
            fields={[
              ["p = 2²⁵⁵ − 19", trace.constants.p],
              ["L: subgroup order", trace.constants.L],
              ["d = −121665 · 121666⁻¹ mod p", trace.constants.d],
              ["Base point B", trace.constants.B],
            ]}
          />
          <Step
            title="3. Expand a disposable secret seed"
            description="SECRET DEMO VALUES. A fresh seed is expanded by native SHA-512."
            fields={[
              ["Disposable seed (hex)", trace.seed],
              ["h = SHA-512(seed)", trace.expanded],
              ["prefix = h[32…63]", trace.prefix],
            ]}
          />
          <Step
            title="4. Clamp the scalar and derive the public key"
            description="h[0] &= 248; h[31] &= 63; h[31] |= 64. Interpret the result as a little-endian integer."
            fields={[
              ["Clamped bytes", trace.clamped],
              ["Secret scalar a", trace.a],
              ["A = [a]B", trace.A],
              ["encode(A)", trace.publicKey],
            ]}
          />
          <Step
            title="5. Derive the deterministic nonce"
            description="This Ed25519 signing nonce does not provide replay protection."
            fields={[
              ["prefix || M", trace.nonceInput],
              ["SHA-512(prefix || M)", trace.nonceHash],
              ["r = LE(nonce hash) mod L", trace.r],
              ["R = [r]B", trace.R],
              ["encode(R)", trace.encodedR],
            ]}
          />
          <Step
            title="6. Bind point, public key, and message"
            description="Hash the concatenation of compressed R, compressed A, and M."
            fields={[
              ["encode(R) || encode(A) || M", trace.challengeInput],
              ["SHA-512(challenge input)", trace.challengeHash],
              ["k = LE(challenge hash) mod L", trace.k],
            ]}
          />
          <Step
            title="7. Complete the signature"
            description="Signature = encode(R) || LE32(S), 64 bytes."
            fields={[
              ["S = (r + k·a) mod L", trace.s],
              ["S encoded little-endian", trace.encodedS],
              ["Signature (hex)", trace.signature],
              ["Signature (Base64)", trace.signatureBase64],
              ["Matches native Ed25519", trace.matches],
            ]}
          />
          <Step
            title="8. Verify using public values"
            description="For these freshly generated subgroup points, check [S]B = R + [k]A."
            fields={[
              ["Left side [S]B", trace.lhs],
              ["Right side R + [k]A", trace.rhs],
              ["Point equality", trace.equal],
              ["Native verification", trace.nativeVerified],
            ]}
          />
          <Card className="surface math-step">
            <h2>9. Every scalar-multiplication round</h2>
            <p>
              256 little-endian bits: conditionally add, then double. Extended
              coordinates represent x=X/Z, y=Y/Z, T=XY/Z.
            </p>
            <pre className="math-value">
              A₀=(Y₁−X₁)(Y₂−X₂); B₀=(Y₁+X₁)(Y₂+X₂); C₀=2dT₁T₂; D₀=2Z₁Z₂;
              E=B₀−A₀; F=D₀−C₀; G=D₀+C₀; H=B₀+A₀; (X₃,Y₃,Z₃,T₃)=(EF,GH,FG,EH).
              Field inverse: Z^(p−2) mod p.
            </pre>
            <Rounds trace={trace} />
            <p>
              <a
                href="https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1"
                target="_blank"
                rel="noreferrer"
              >
                RFC 8032, section 5.1
              </a>
            </p>
          </Card>
        </>
      )}
    </section>
  );
}
