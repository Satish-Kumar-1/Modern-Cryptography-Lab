import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { Api, SignedMessage } from "@/lib/api.js";
import { StorageView } from "./storage-view";

const users = [
  { name: "Alice", publicKey: "public-alice", trusted: true },
  { name: "Bob", publicKey: "public-bob", trusted: false },
];
const message: SignedMessage = {
  senderId: "Alice",
  receiverId: "Bob",
  message: "Exact plaintext",
  signature: "exact-signature",
};
function fixture() {
  const listUsers = vi.fn().mockResolvedValue(users);
  const getInbox = vi.fn(async (name: string) =>
    name === "Bob" ? [message] : [],
  );
  const getUserKeys = vi.fn(async (name: string) => ({
    ...users.find((user) => user.name === name),
    privateKey: `private-${name}`,
  }));
  return { listUsers, getInbox, getUserKeys };
}
afterEach(() => vi.useRealTimers());

it("joins real API records into visible key, connection, and message tables", async () => {
  const api = fixture();
  render(<StorageView api={api as unknown as Api} />);
  await screen.findByText("2 users · 1 messages");
  const connections = screen.getByRole("region", { name: "Connections" });
  expect(within(connections).getByText("Alice")).toBeInTheDocument();
  expect(within(connections).getByText("Bob")).toBeInTheDocument();
  expect(screen.getByText("Exact plaintext")).toBeInTheDocument();
  expect(screen.getByText("exact-signature")).toBeInTheDocument();
  expect(api.getUserKeys).not.toHaveBeenCalled();
  fireEvent.click(
    screen.getByRole("button", { name: "Reveal Alice private key" }),
  );
  await screen.findByText("private-Alice");
  fireEvent.click(
    screen.getByRole("button", { name: "Hide Alice private key" }),
  );
  expect(screen.queryByText("private-Alice")).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Filter storage"), {
    target: { value: "does-not-exist" },
  });
  expect(screen.queryByText("Exact plaintext")).not.toBeInTheDocument();
});

it("refreshes every three seconds, skips overlapping loads, and stops after leaving", async () => {
  vi.useFakeTimers();
  const api = fixture();
  const { unmount } = render(<StorageView api={api as unknown as Api} />);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  expect(api.listUsers).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2999);
  });
  expect(api.listUsers).toHaveBeenCalledTimes(1);
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1);
  });
  expect(api.listUsers).toHaveBeenCalledTimes(2);
  let complete!: (value: typeof users) => void;
  api.listUsers.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        complete = resolve;
      }),
  );
  await act(async () => {
    await vi.advanceTimersByTimeAsync(9000);
  });
  expect(api.listUsers).toHaveBeenCalledTimes(3);
  const inboxCalls = api.getInbox.mock.calls.length;
  unmount();
  await act(async () => {
    complete(users);
    await vi.advanceTimersByTimeAsync(6000);
  });
  expect(api.listUsers).toHaveBeenCalledTimes(3);
  expect(api.getInbox).toHaveBeenCalledTimes(inboxCalls);
});

it("keeps the last snapshot on errors and hides keys after a directory change", async () => {
  const api = fixture();
  render(<StorageView api={api as unknown as Api} />);
  await screen.findByText("Exact plaintext");
  fireEvent.click(
    screen.getByRole("button", { name: "Reveal Alice private key" }),
  );
  await screen.findByText("private-Alice");
  api.listUsers.mockRejectedValueOnce(new Error("Backend offline"));
  fireEvent.click(screen.getByRole("button", { name: "Refresh storage" }));
  await screen.findByText(/Showing the last successful snapshot/);
  expect(screen.getByText("Exact plaintext")).toBeInTheDocument();
  api.listUsers.mockResolvedValueOnce([
    { ...users[0], publicKey: "replacement-public" },
    users[1],
  ]);
  fireEvent.click(screen.getByRole("button", { name: "Refresh storage" }));
  await waitFor(() =>
    expect(
      screen.getAllByText("replacement-public", { selector: "code" }).length,
    ).toBeGreaterThan(0),
  );
  await waitFor(() =>
    expect(screen.queryByText("private-Alice")).not.toBeInTheDocument(),
  );
});
