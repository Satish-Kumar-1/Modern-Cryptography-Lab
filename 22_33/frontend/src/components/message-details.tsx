import { useState } from "react";
import { Button } from "@/components/ui/button";
import type { SignedMessage } from "@/lib/api.js";
import {
  Collapsible,
  CollapsibleTrigger,
  CollapsibleContent,
} from "@/components/ui/collapsible";
import { payload } from "@/lib/math.js";

export function MessageDetails({ message }: { message: SignedMessage }) {
  const [copied, setCopied] = useState("");
  return (
    <Collapsible className="message-details" defaultOpen>
      <CollapsibleTrigger asChild>
        <Button variant="ghost" size="sm">
          Inspect Ed25519 signature & signed package
        </Button>
      </CollapsibleTrigger>
      <CollapsibleContent className="detail-content">
        <dl>
          <dt>Replay nonce</dt>
          <dd>{message.nonce || "Legacy package — no nonce"}</dd>
          <dt>Sender</dt>
          <dd>{message.senderId}</dd>
          <dt>Recipient</dt>
          <dd>{message.receiverId}</dd>
          <dt>Ed25519 signature · Base64</dt>
          <dd>{message.signature}</dd>
        </dl>
        <dl>
          <dt>Exact signed payload</dt>
          <dd>
            {payload(
              message.senderId,
              message.receiverId,
              message.message,
              message.nonce,
            )}
          </dd>
        </dl>
        <p>
          Accepted on delivery. Opening these details does not verify the
          signature again.
        </p>
        <div className="reader-actions">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(
                  JSON.stringify(message, null, 2),
                );
                setCopied("Copied JSON");
              } catch {
                setCopied("Copy unavailable");
              }
            }}
          >
            {copied || "Copy signed package"}
          </Button>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
export function Timestamp({ message }: { message: SignedMessage }) {
  const value = message.timestamp;
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
      value,
    ) &&
    Number.isFinite(Date.parse(value)) ? (
    <time className="message-time" dateTime={value}>
      {new Date(value).toLocaleString()}
    </time>
  ) : (
    <span className="message-time unavailable-time">
      Not provided by server
    </span>
  );
}
export function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty-state">
      <span className="empty-icon">▤</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
