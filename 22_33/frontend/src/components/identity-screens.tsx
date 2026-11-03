import { useState } from "react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import type { UserKeys } from "@/lib/api.js";

export function IdentityEntry({
  creating,
  name,
  onName,
  busy,
  notice,
  onLookup,
  onCreate,
  onBack,
}: {
  creating: boolean;
  name: string;
  onName: (name: string) => void;
  busy: boolean;
  notice: string;
  onLookup: () => void;
  onCreate: () => Promise<void>;
  onBack: () => void;
}) {
  return (
    <main className="entry-screen identity-entry">
      <Card className="identity-entry-card">
        <CardHeader>
          <CardTitle>
            <h1>
              {creating ? "This identity is available" : "Open your workspace"}
            </h1>
          </CardTitle>
          <CardDescription>
            {creating
              ? "Create this demo identity and its Ed25519 keys."
              : "Enter a username to open signed mail and security tests."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              if (creating) void onCreate().catch(() => {});
              else onLookup();
            }}
          >
            <FieldGroup>
              <Field data-disabled={busy || creating}>
                <FieldLabel htmlFor="username">
                  {creating ? "New username" : "Username"}
                </FieldLabel>
                <Input
                  id="username"
                  value={name}
                  onChange={(event) => onName(event.target.value)}
                  required
                  maxLength={64}
                  autoComplete="off"
                  placeholder="e.g. Alice"
                  disabled={busy || creating}
                />
              </Field>
              <Button type="submit" disabled={busy || !name.trim()}>
                {busy
                  ? creating
                    ? "Generating keys…"
                    : "Loading identity…"
                  : creating
                    ? "Create identity"
                    : "Continue →"}
              </Button>
            </FieldGroup>
          </form>
          {notice && (
            <Alert variant="destructive" className="mt-4">
              <AlertTitle>Could not continue</AlertTitle>
              <AlertDescription>{notice}</AlertDescription>
            </Alert>
          )}
          {creating ? (
            <Button
              className="mt-4"
              variant="ghost"
              disabled={busy}
              onClick={onBack}
            >
              ← Use another username
            </Button>
          ) : (
            <p className="entry-note">
              Classroom demo. A username selects an identity; it does not
              authenticate ownership.
            </p>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

export function KeyVault({
  pair,
  onContinue,
}: {
  pair: UserKeys;
  onContinue: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const [notice, setNotice] = useState("");
  const copy = async (privateKey: boolean) => {
    if (privateKey && !revealed) return;
    try {
      await navigator.clipboard.writeText(
        privateKey ? pair.privateKey : pair.publicKey,
      );
      setNotice(
        privateKey
          ? "Private key copied. Keep it secret."
          : "Public key copied.",
      );
    } catch {
      setNotice(
        "Clipboard unavailable. Select the revealed key and copy it manually.",
      );
    }
  };
  return (
    <main className="vault-screen">
      <div className="vault-heading">
        <div>
          <span className="eyebrow">PAGE 1 / KEY VAULT</span>
          <h1>Your Cryptographic Identity</h1>
          <p>Inspect your identity before opening the mail workspace.</p>
        </div>
        <Badge variant="outline">Ed25519</Badge>
      </div>
      <Card className="identity-summary">
        <div className="identity-symbol" aria-hidden="true">
          ◇
        </div>
        <div>
          <span className="field-label">USERNAME</span>
          <h2>@{pair.name}</h2>
        </div>
        <Badge variant="secondary">
          {pair.trusted ? "Server-trusted key" : "Untrusted key"}
        </Badge>
      </Card>
      <div className="key-grid">
        <Card className="vault-key-card">
          <CardHeader>
            <div className="key-card-heading">
              <div>
                <span className="field-label">VERIFICATION KEY / X.509</span>
                <h2>Public key</h2>
              </div>
              <Button variant="outline" onClick={() => void copy(false)}>
                Copy public key
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <pre
              className="identity-key"
              aria-label="Your public key"
              tabIndex={0}
            >
              {pair.publicKey}
            </pre>
            <p>X.509 · Base64. Share this key to verify your signatures.</p>
          </CardContent>
        </Card>
        <Card className="vault-key-card private-card">
          <CardHeader>
            <div className="key-card-heading">
              <div>
                <span className="field-label">SIGNING KEY / PKCS#8</span>
                <h2>Private key</h2>
              </div>
              <Button
                variant="outline"
                disabled={!revealed}
                onClick={() => void copy(true)}
              >
                Copy private key
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="identity-key private-key-block">
              {revealed ? (
                <span aria-label="Your private key">{pair.privateKey}</span>
              ) : (
                <Button variant="outline" onClick={() => setRevealed(true)}>
                  Reveal private key
                </Button>
              )}
            </div>
            <p>PKCS#8 · Base64. Keep your private key secret.</p>
            {revealed && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setRevealed(false);
                  setNotice("");
                }}
              >
                Hide private key
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
      <Alert className="mt-6">
        <AlertTitle>Keep private keys secret · test identities only</AlertTitle>
        <AlertDescription>
          This classroom server retains keys, and anyone who knows the username
          can retrieve its private key. Hiding it here protects against casual
          viewing only.
        </AlertDescription>
      </Alert>
      <p className="notice" role="status">
        {notice}
      </p>
      <div className="vault-footer">
        <span>
          The displayed keys are cleared when you enter the workspace or log
          out.
        </span>
        <Button size="lg" onClick={onContinue}>
          Continue to Mail Workspace →
        </Button>
      </div>
    </main>
  );
}
