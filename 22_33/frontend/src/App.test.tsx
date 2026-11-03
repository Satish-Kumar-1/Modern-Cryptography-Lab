import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SignedMessage, UserKeys } from "@/lib/api.js";

const fake = vi.hoisted(() => ({
  getUserKeys: vi.fn(),
  createUser: vi.fn(),
  listUsers: vi.fn(),
  getInbox: vi.fn(),
  send: vi.fn(),
}));
vi.mock("@/lib/api.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api.js")>()),
  createApi: () => fake,
}));
import { ApiError } from "@/lib/api.js";
import App from "./App";

const pair = (name: string): UserKeys => ({
  name,
  publicKey: "public-" + name,
  privateKey: "private-" + name,
  trusted: true,
});
const entry = (senderId: string, body = "Hello"): SignedMessage => ({
  senderId,
  receiverId: "Alice",
  message: body,
  signature: "example-signature",
});
async function login(name = "Alice") {
  fireEvent.change(screen.getByLabelText("Username"), {
    target: { value: name },
  });
  fireEvent.click(screen.getByRole("button", { name: "Continue →" }));
  await screen.findByRole("heading", { name: "Inbox" });
}
async function mail() {
  await login();
  // First entry also imports the separately bundled workspace and its UI dependencies.
  await screen.findAllByText("Backend connected", {}, { timeout: 5000 });
}
beforeEach(() => {
  vi.clearAllMocks();
  fake.getUserKeys.mockImplementation(async (name: string) => pair(name));
  fake.createUser.mockImplementation(async ({ name }: { name: string }) =>
    pair(name),
  );
  fake.listUsers.mockResolvedValue(
    ["Alice", "Bob", "Mallory"].map((name) => ({
      name,
      publicKey: "public-" + name,
      trusted: true,
    })),
  );
  fake.getInbox.mockImplementation(async (name: string) =>
    name === "Alice"
      ? [entry("Bob", "First message"), entry("Mallory", "Second message")]
      : [],
  );
  fake.send.mockResolvedValue({ delivered: true });
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  });
});
describe("React identity and mail flow", () => {
  it("opens an existing identity in the copyable vault without browser storage", async () => {
    render(<App />);
    expect(
      screen.queryByRole("button", { name: "Logout ↗" }),
    ).not.toBeInTheDocument();
    await login();
    fireEvent.click(screen.getByRole("button", { name: "Key vault" }));
    await screen.findByRole("heading", { name: "Your Cryptographic Identity" });
    expect(screen.queryByLabelText("Your private key")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy private key" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Reveal private key" }));
    expect(screen.getByLabelText("Your private key")).toHaveTextContent(
      "private-Alice",
    );
    fireEvent.click(screen.getByRole("button", { name: "Copy private key" }));
    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledWith(
        "private-Alice",
      ),
    );
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    fireEvent.click(screen.getByRole("button", { name: "Hide private key" }));
    expect(screen.queryByLabelText("Your private key")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy private key" }),
    ).toBeDisabled();
  });
  it("routes only a missing username to creation and opens the new pair", async () => {
    fake.getUserKeys.mockRejectedValueOnce(new ApiError("Not found", 404));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "Carol" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue →" }));
    await screen.findByRole("heading", { name: "This identity is available" });
    fireEvent.click(
      screen.getByRole("button", {
        name: "Create identity",
      }),
    );
    await screen.findByRole("heading", { name: "Your Cryptographic Identity" });
    expect(fake.createUser).toHaveBeenCalledWith({
      name: "Carol",
      trusted: true,
    });
    expect(screen.getByRole("heading", { name: "@Carol" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Your private key")).not.toBeInTheDocument();
  });
  it("keeps connection errors on Home", async () => {
    fake.getUserKeys.mockRejectedValueOnce(new ApiError("Backend offline", 0));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "Alice" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue →" }));
    await screen.findByText("Backend offline");
    expect(
      screen.getByRole("heading", { name: "Open your workspace" }),
    ).toBeInTheDocument();
    expect(fake.createUser).not.toHaveBeenCalled();
  });
  it("allows retrying identity creation after a backend error", async () => {
    fake.getUserKeys.mockRejectedValueOnce(new ApiError("Not found", 404));
    fake.createUser.mockRejectedValueOnce(
      new ApiError("Generation failed", 500),
    );
    render(<App />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "Carol" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue →" }));
    const slider = await screen.findByRole("button", {
      name: "Create identity",
    });
    fireEvent.click(slider);
    await screen.findByText("Generation failed");
    await waitFor(() => expect(slider).toBeEnabled());
    expect(screen.queryByText("Identity created")).not.toBeInTheDocument();
    fireEvent.click(slider);
    await screen.findByRole("heading", { name: "Your Cryptographic Identity" });
    expect(fake.createUser).toHaveBeenCalledTimes(2);
  });
  it("returns a concurrently registered name to login instead of creating twice", async () => {
    fake.getUserKeys.mockRejectedValueOnce(new ApiError("Not found", 404));
    fake.createUser.mockRejectedValueOnce(new ApiError("Already exists", 409));
    render(<App />);
    fireEvent.change(screen.getByLabelText("Username"), {
      target: { value: "Carol" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue →" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Create identity",
      }),
    );
    await screen.findByText(/That username was just registered/);
    expect(
      screen.getByRole("heading", { name: "Open your workspace" }),
    ).toBeInTheDocument();
  });
  it("shows mail from every sender and exact signatures with no fabricated time", async () => {
    render(<App />);
    await mail();
    expect(screen.queryByLabelText("Your private key")).not.toBeInTheDocument();
    const list = screen.getByRole("list");
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    fireEvent.click(within(list).getByRole("button", { name: /Bob/ }));
    const reader = screen.getByRole("article", { name: "Selected message" });
    expect(within(reader).getByText("First message")).toBeInTheDocument();
    expect(
      within(reader).getByText("Not provided by server"),
    ).toBeInTheDocument();
    expect(within(reader).getByText("example-signature")).toBeInTheDocument();
    expect(within(reader).getByText("✓ Backend accepted")).toBeInTheDocument();
  });
  it("searches by public key, opens full-key compose, and preserves exact content", async () => {
    render(<App />);
    await mail();
    fireEvent.change(
      screen.getByLabelText("Find users by username or public key"),
      { target: { value: "public-Bob" } },
    );
    fireEvent.click(await screen.findByRole("option", { name: /Bob/ }));
    expect(
      screen.getByRole("heading", { name: "Message to Bob" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Recipient public key" }),
    ).toHaveTextContent("public-Bob");
    fireEvent.change(screen.getByLabelText("Message", { exact: true }), {
      target: { value: "  exact\ncontent  " },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign & Send →" }));
    await waitFor(() =>
      expect(fake.send).toHaveBeenCalledWith({
        sender: "Alice",
        recipient: "Bob",
        content: "  exact\ncontent  ",
      }),
    );
    await screen.findByText("Signed and delivered to Bob.");
  });
  it("updates backend status when sending fails and preserves the draft", async () => {
    fake.send.mockRejectedValueOnce(new ApiError("Backend offline", 0));
    render(<App />);
    await mail();
    fireEvent.change(
      screen.getByLabelText("Find users by username or public key"),
      { target: { value: "Bob" } },
    );
    fireEvent.click(await screen.findByRole("option", { name: "Bob" }));
    fireEvent.change(screen.getByLabelText("Message", { exact: true }), {
      target: { value: "Keep this draft" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign & Send →" }));
    await screen.findByText("Backend offline");
    expect(
      (await screen.findAllByText("Backend request failed")).length,
    ).toBeGreaterThan(0);
    expect(screen.getByLabelText("Message", { exact: true })).toHaveValue(
      "Keep this draft",
    );
  });
  it("clears identity and private keys on logout, including a delayed vault fetch", async () => {
    render(<App />);
    await mail();
    let finish!: (value: UserKeys) => void;
    fake.getUserKeys.mockImplementationOnce(
      () =>
        new Promise<UserKeys>((resolve) => {
          finish = resolve;
        }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Key vault" }));
    fireEvent.click(screen.getByRole("button", { name: "Logout ↗" }));
    await act(async () => finish(pair("Alice")));
    expect(
      screen.getByRole("heading", { name: "Open your workspace" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Your private key")).not.toBeInTheDocument();
    expect(screen.queryByText("private-Alice")).not.toBeInTheDocument();
  });
  it("does not repopulate inbox after logout while requests are pending", async () => {
    let finish!: (value: SignedMessage[]) => void;
    fake.getInbox.mockImplementationOnce(
      () =>
        new Promise<SignedMessage[]>((resolve) => {
          finish = resolve;
        }),
    );
    render(<App />);
    await login();
    await waitFor(() => expect(fake.getInbox).toHaveBeenCalled());
    fireEvent.click(screen.getByRole("button", { name: "Logout ↗" }));
    await act(async () => finish([entry("Bob", "stale message")]));
    expect(screen.queryByText("stale message")).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Open your workspace" }),
    ).toBeInTheDocument();
  });
});
