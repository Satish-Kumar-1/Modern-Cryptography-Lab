import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import type { Api } from "@/lib/api.js";
import { AttackLab } from "./attack-lab";

it("requires explicit actions and replays an unchanged capture without signing", async () => {
  const packet = {
    messageId: "unique-1",
    senderId: "alice",
    receiverId: "bob",
    message: "Transfer 10 credits to Bob.",
    signature: "",
  };
  const signed = { ...packet, signature: "AQID" };
  const result = {
    signatureValid: true,
    trusted: true,
    keyMatchesPinned: true,
    recipientMatches: true,
    duplicate: false,
    accepted: true,
    reason: "ACCEPTED",
    verificationKeyFingerprint: "pin",
    pinnedKeyFingerprint: "pin",
    payload: "payload",
    payloadBase64: "cGF5bG9hZA==",
    comparisonDigest: "digest",
  };
  const lab = vi.fn(async (path = "", body?: unknown, method?: string) => {
    if (!path)
      return {
        sessionId: "session",
        identities: ["alice", "bob", "mallory"].map((name) => ({
          name,
          publicKey: name + "-public",
          privateKey: name + "-private",
          fingerprint: "pin",
        })),
      };
    if (method === "GET")
      return {
        inbox: [],
        trustedKeys: { "bob:alice": "alice-public" },
        events: [],
      };
    if (path.endsWith("/prepare")) return packet;
    if (path.endsWith("/sign")) return signed;
    if (path.endsWith("/deliver") || path.endsWith("/verify")) return result;
    return body;
  });
  render(<AttackLab api={{ lab } as unknown as Api} />);
  expect(lab).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Create isolated lab" }));
  await screen.findByRole("button", { name: "Prepare new message ID" });
  fireEvent.click(
    screen.getByRole("button", { name: "Prepare new message ID" }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Sign current package" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Sign current package" }));
  await waitFor(() =>
    expect(screen.getByLabelText("signature")).toHaveValue("AQID"),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Capture signed package" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Capture signed package" }),
  );
  fireEvent.change(screen.getByLabelText("message"), {
    target: { value: "edited after capture" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Deliver again without re-signing" }),
  );
  await screen.findByText("Captured package — exact replay delivery");
  const delivered = lab.mock.calls.find((c) => c[0]?.endsWith("/deliver"));
  expect(delivered?.[1]).toEqual({
    packet: signed,
    recipientId: "bob",
    replayProtection: false,
  });
  expect(lab.mock.calls.filter((c) => c[0]?.endsWith("/sign"))).toHaveLength(1);
  fireEvent.change(screen.getByLabelText("message"), {
    target: { value: "changed again" },
  });
  expect(
    screen.queryByText("Captured package — exact replay delivery"),
  ).not.toBeInTheDocument();
});
it("reports transport failures without claiming attack rejection", async () => {
  const lab = vi.fn().mockRejectedValue(new Error("Backend offline"));
  render(<AttackLab api={{ lab } as unknown as Api} />);
  fireEvent.click(screen.getByRole("button", { name: "Create isolated lab" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Backend offline");
  expect(screen.queryByText("ACCEPTED")).not.toBeInTheDocument();
});
