// @vitest-environment node
import { beforeEach, expect, it, vi } from "vitest";
import type { Api, UserKeys, SignedMessage } from "./api.js";
import { payload } from "./math.js";
import { createLab, runExperiment } from "./attack-experiments";
import type { Exploit, LabIdentities } from "./attack-experiments";

let api: Api, lab: LabIdentities;
const b64 = (value: ArrayBuffer) => Buffer.from(value).toString("base64");
beforeEach(async () => {
  const identities = new Map<
    string,
    { value: UserKeys; keys: CryptoKeyPair }
  >();
  const inbox: SignedMessage[] = [];
  const createUser = vi.fn(
    async ({ name, trusted = true }: { name: string; trusted?: boolean }) => {
      const keys = await crypto.subtle.generateKey("Ed25519", true, [
        "sign",
        "verify",
      ]);
      const value = {
        name,
        trusted,
        publicKey: b64(await crypto.subtle.exportKey("spki", keys.publicKey)),
        privateKey: b64(
          await crypto.subtle.exportKey("pkcs8", keys.privateKey),
        ),
      };
      identities.set(name, { value, keys });
      return value;
    },
  );
  api = {
    createUser,
    sign: vi.fn(async ({ sender, recipient, content }) => {
      const signer = identities.get(sender)!;
      const signature = await crypto.subtle.sign(
        "Ed25519",
        signer.keys.privateKey,
        new TextEncoder().encode(payload(sender, recipient, content)),
      );
      return {
        senderId: sender,
        receiverId: recipient,
        message: content,
        signature: b64(signature),
      };
    }),
    receive: vi.fn(async (recipient, message) => {
      const signer = identities.get(message.senderId);
      const accepted =
        !!signer?.value.trusted &&
        message.receiverId === recipient &&
        (await crypto.subtle.verify(
          "Ed25519",
          signer.keys.publicKey,
          Buffer.from(message.signature, "base64"),
          new TextEncoder().encode(
            payload(message.senderId, message.receiverId, message.message),
          ),
        ));
      if (accepted) inbox.push({ ...message });
      return { accepted };
    }),
    getInbox: vi.fn(async (name) =>
      inbox.filter((message) => message.receiverId === name),
    ),
  } as unknown as Api;
  lab = await createLab(api, () => true);
});
for (const exploit of [
  "message",
  "signature",
  "impersonation",
  "untrusted",
  "replay",
  "plaintext",
] as Exploit[]) {
  it(`runs ${exploit} using real native Ed25519 signatures and observed responses`, async () => {
    const result = await runExperiment(
      api,
      lab,
      exploit,
      "  Exact café\nmessage  ",
      () => true,
    );
    expect(result.outcome).toBe(
      ["replay", "plaintext"].includes(exploit) ? "gap" : "defended",
    );
    expect(JSON.stringify(result.evidence)).not.toContain(
      lab.attacker.privateKey,
    );
    if (exploit === "replay") {
      expect(result.evidence.matchingInboxCopies).toBe(2);
      expect(api.receive).toHaveBeenCalledTimes(2);
      expect(vi.mocked(api.receive).mock.calls[0][1]).toEqual(
        vi.mocked(api.receive).mock.calls[1][1],
      );
    }
    if (exploit === "signature") {
      const submitted = result.evidence.submitted as SignedMessage;
      expect(Buffer.from(submitted.signature, "base64")).toHaveLength(64);
    }
    if (exploit === "impersonation")
      expect(result.steps[1].value).toContain(
        "Attacker key verifies: true; claimed sender key verifies: false",
      );
    if (exploit === "plaintext") expect(api.receive).not.toHaveBeenCalled();
  });
}
it("does not treat a transport failure as successful rejection", async () => {
  vi.mocked(api.receive).mockRejectedValueOnce(new Error("Backend offline"));
  await expect(
    runExperiment(api, lab, "message", "Hello", () => true),
  ).rejects.toThrow("Backend offline");
});
it("stops additional delivery requests when the lab is unmounted", async () => {
  let active = true;
  const sign = api.sign;
  api.sign = async (body) => {
    const signed = await sign(body);
    active = false;
    return signed;
  };
  await expect(
    runExperiment(api, lab, "replay", "Hello", () => active),
  ).rejects.toThrow("cancelled");
  expect(api.receive).not.toHaveBeenCalled();
});
