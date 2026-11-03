import type { Api, SignedMessage, User, UserKeys } from "./api.js";
import { payload } from "./math.js";

export type Exploit =
  | "message"
  | "signature"
  | "impersonation"
  | "untrusted"
  | "replay"
  | "plaintext";
export type LabIdentities = {
  sender: User;
  receiver: User;
  attacker: UserKeys;
};
export type ExperimentResult = {
  outcome: "defended" | "gap" | "unexpected";
  summary: string;
  steps: { label: string; value: string }[];
  evidence: Record<string, unknown>;
  countermeasure: string;
};
const publicIdentity = ({ name, publicKey, trusted }: User): User => ({
  name,
  publicKey,
  trusted,
});
export function assertActive(current: () => boolean) {
  if (!current()) throw new Error("Experiment cancelled.");
}
export async function createLab(
  api: Api,
  current: () => boolean,
): Promise<LabIdentities> {
  const id = crypto.randomUUID().slice(0, 12);
  const create = async (role: string, trusted: boolean) => {
    assertActive(current);
    return api.createUser({ name: `lab-${id}-${role}`, trusted });
  };
  const sender = publicIdentity(await create("alice", true));
  const receiver = publicIdentity(await create("bob", true));
  const attacker = await create("mallory", false);
  assertActive(current);
  return { sender, receiver, attacker };
}
const bytes = (base64: string) =>
  Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
const base64 = (value: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(value)));
async function verify(message: SignedMessage, publicKey: string) {
  const key = await crypto.subtle.importKey(
    "spki",
    bytes(publicKey),
    "Ed25519",
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "Ed25519",
    key,
    bytes(message.signature),
    new TextEncoder().encode(
      payload(message.senderId, message.receiverId, message.message),
    ),
  );
}
export async function runExperiment(
  api: Api,
  lab: LabIdentities,
  exploit: Exploit,
  content: string,
  current: () => boolean,
): Promise<ExperimentResult> {
  const call = async <T>(request: () => Promise<T>): Promise<T> => {
    assertActive(current);
    const value = await request();
    assertActive(current);
    return value;
  };
  const receiver = lab.receiver.name;
  const original = await call(() =>
    api.sign({
      sender: exploit === "untrusted" ? lab.attacker.name : lab.sender.name,
      recipient: receiver,
      content,
    }),
  );
  const validOriginal = await verify(
    original,
    exploit === "untrusted" ? lab.attacker.publicKey : lab.sender.publicKey,
  );
  assertActive(current);
  if (!validOriginal)
    throw new Error(
      "Baseline signature did not verify. No attack conclusion can be drawn.",
    );
  const steps = [
    {
      label: "Baseline",
      value: "Original signature verified with native Ed25519.",
    },
  ];
  const receive = (message: SignedMessage) =>
    call(() => api.receive(receiver, message));
  if (exploit === "replay") {
    const previous = await call(() => api.getInbox(receiver));
    const before = previous.filter(
      (m) =>
        m.senderId === original.senderId &&
        m.receiverId === receiver &&
        m.message === content &&
        m.signature === original.signature,
    ).length;
    const first = await receive(original);
    const second = await receive(original);
    const inbox = await call(() => api.getInbox(receiver));
    const copies = inbox.filter(
      (m) =>
        m.senderId === original.senderId &&
        m.receiverId === receiver &&
        m.message === content &&
        m.signature === original.signature,
    ).length;
    const addedCopies = copies - before;
    const vulnerable = first.accepted && second.accepted && addedCopies === 2;
    return {
      outcome: vulnerable ? "gap" : "unexpected",
      summary: vulnerable
        ? "Replay accepted: the same signed package was delivered twice."
        : "Replay behavior differed from the expected duplicate acceptance. Inspect the responses.",
      steps: [
        ...steps,
        { label: "First delivery", value: String(first.accepted) },
        { label: "Identical replay", value: String(second.accepted) },
        {
          label: "Matching inbox copies before → after",
          value: `${before} → ${copies} (${addedCopies} added)`,
        },
      ],
      evidence: {
        original,
        first,
        second,
        matchingInboxCopies: copies,
        previousMatchingCopies: before,
        addedCopies,
      },
      countermeasure:
        "Sign a unique message ID or counter with the message; atomically reject IDs already seen by this recipient. Validate timestamps and an allowed age where needed.",
    };
  }
  if (exploit === "plaintext") {
    const wireJson = JSON.stringify(original);
    const readable = JSON.parse(wireJson).message === content;
    return {
      outcome: readable ? "gap" : "unexpected",
      summary: "The signed API package contains the readable message text.",
      steps: [
        ...steps,
        { label: "Application JSON", value: content },
        {
          label: "Confidentiality",
          value:
            "Signing does not encrypt the payload. HTTPS protects transport; this is not a network sniffing demonstration.",
        },
      ],
      evidence: {
        signedApiResponse: original,
        serializedApplicationData: wireJson,
        readable,
      },
      countermeasure:
        "Use authenticated encryption such as AES-GCM with securely exchanged keys for message confidentiality, alongside HTTPS and digital signatures.",
    };
  }
  let submitted = { ...original };
  if (exploit === "message") submitted.message += " [modified after signing]";
  if (exploit === "signature") {
    const altered = bytes(original.signature);
    altered[0] ^= 1;
    submitted.signature = base64(altered);
  }
  if (exploit === "impersonation") {
    const key = await crypto.subtle.importKey(
      "pkcs8",
      bytes(lab.attacker.privateKey),
      "Ed25519",
      false,
      ["sign"],
    );
    const forgedSignature = await crypto.subtle.sign(
      "Ed25519",
      key,
      new TextEncoder().encode(payload(original.senderId, receiver, content)),
    );
    submitted = { ...original, signature: base64(forgedSignature) };
    const validWithAttacker = await verify(submitted, lab.attacker.publicKey);
    const validWithClaimedSender = await verify(
      submitted,
      lab.sender.publicKey,
    );
    steps.push({
      label: "Same claimed-sender payload, attacker key",
      value: `Attacker key verifies: ${validWithAttacker}; claimed sender key verifies: ${validWithClaimedSender}.`,
    });
  }
  const response = await receive(submitted);
  const defended = response.accepted === false;
  const protections = {
    message:
      "Verify the signature over the exact sender, recipient, and message bytes; reject modified packages.",
    signature:
      "Verify the full Ed25519 signature and reject malformed or changed signatures.",
    impersonation:
      "Bind sender identities to authentic public keys using verified fingerprints or certificates. A username alone does not authenticate the person using this demo.",
    untrusted:
      "Reject keys absent from the trusted identity registry. Establish trust through authenticated distribution, not a user-selected flag.",
  };
  return {
    outcome: defended ? "defended" : "unexpected",
    summary: defended
      ? exploit === "untrusted"
        ? "A cryptographically valid signature from an untrusted sender was rejected."
        : "The backend rejected the submitted attack package."
      : "Unexpected: the backend accepted this attack package.",
    steps: [
      ...steps,
      {
        label: "Mutation / policy",
        value:
          exploit === "message"
            ? "Message changed; original signature retained."
            : exploit === "signature"
              ? "One signature bit flipped; message unchanged."
              : exploit === "untrusted"
                ? "Original message and valid signature unchanged; sender is not trusted."
                : "Claimed identity unchanged; signed with Mallory's private key.",
      },
      { label: "Backend accepted", value: String(response.accepted) },
    ],
    evidence: { original, submitted, response },
    countermeasure: protections[exploit],
  };
}
