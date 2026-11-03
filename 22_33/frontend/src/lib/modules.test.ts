// @vitest-environment node
import { expect, it } from "vitest";
import { createApi } from "./api.js";
import { fromHex, traceSignature, payload } from "./math.js";

it("exports a working REST helper with encoded demo-key lookup", async () => {
  const urls: string[] = [];
  const api = createApi("", async (input, init) => {
    urls.push(String(input));
    expect(init?.cache).toBe("no-store");
    return new Response(
      JSON.stringify({
        name: "A B",
        publicKey: "public-example",
        privateKey: "private-example",
      }),
    );
  });
  expect((await api.getUserKeys("A B/#")).privateKey).toBe("private-example");
  expect(urls).toEqual(["/api/users/A%20B%2F%23/keys"]);
});
it("the imported ESM math implementation matches RFC 8032 and native Ed25519", async () => {
  const trace = await traceSignature(
    fromHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    new Uint8Array(),
    false,
  );
  expect(trace.publicKey).toBe(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  );
  expect(trace.signature).toBe(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  );
  expect(trace.matches && trace.nativeVerified).toBe(true);
  expect(payload("A", "B", "  hi\n")).toBe("QQ==:Qg==:ICBoaQo=");
});
