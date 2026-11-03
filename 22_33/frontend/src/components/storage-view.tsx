import { useCallback, useEffect, useRef, useState } from "react";
import type { Api, SignedMessage, User, UserKeys } from "@/lib/api.js";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
  TableCaption,
} from "@/components/ui/table";
import { errorMessage } from "@/lib/use-task";

type StoredMessage = { mailbox: string; packet: SignedMessage };
type Snapshot = { users: User[]; messages: StoredMessage[]; updated: Date };

export function StorageView({ api }: { api: Api }) {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [keys, setKeys] = useState<Record<string, UserKeys>>({});
  const [keyBusy, setKeyBusy] = useState<Record<string, boolean>>({});
  const active = useRef(false);
  const loading = useRef(false);
  const keyLocks = useRef(new Set<string>());
  const refresh = useCallback(async () => {
    if (loading.current) return;
    loading.current = true;
    if (active.current) setBusy(true);
    try {
      const users = (await api.listUsers()).sort((a, b) =>
        a.name.localeCompare(b.name),
      );
      if (!active.current) return;
      const inboxes = await Promise.all(
        users.map(async (user) => ({
          mailbox: user.name,
          messages: await api.getInbox(user.name),
        })),
      );
      if (!active.current) return;
      setSnapshot({
        users,
        messages: inboxes.flatMap(({ mailbox, messages }) =>
          messages.map((packet) => ({ mailbox, packet })),
        ),
        updated: new Date(),
      });
      setError("");
    } catch (failure) {
      if (active.current) setError(errorMessage(failure));
    } finally {
      loading.current = false;
      if (active.current) setBusy(false);
    }
  }, [api]);
  useEffect(() => {
    active.current = true;
    queueMicrotask(() => {
      if (active.current) void refresh();
    });
    const timer = window.setInterval(() => void refresh(), 3000);
    return () => {
      active.current = false;
      window.clearInterval(timer);
    };
  }, [refresh]);
  const revealKey = async (user: User) => {
    if (keyLocks.current.has(user.name)) return;
    keyLocks.current.add(user.name);
    setKeyBusy((previous) => ({ ...previous, [user.name]: true }));
    try {
      const pair = await api.getUserKeys(user.name);
      if (active.current)
        setKeys((previous) => ({ ...previous, [user.name]: pair }));
    } catch (failure) {
      if (active.current) setError(errorMessage(failure));
    } finally {
      keyLocks.current.delete(user.name);
      if (active.current)
        setKeyBusy((previous) => ({ ...previous, [user.name]: false }));
    }
  };
  const matches = (...values: string[]) =>
    values.join("\n").toLocaleLowerCase().includes(query.toLocaleLowerCase());
  const users = snapshot?.users ?? [];
  const messages = snapshot?.messages ?? [];
  const connections = new Map<
    string,
    { sender: string; recipient: string; count: number }
  >();
  for (const { mailbox, packet } of messages) {
    const id = JSON.stringify([packet.senderId, mailbox]);
    const entry = connections.get(id);
    if (entry) entry.count++;
    else
      connections.set(id, {
        sender: packet.senderId,
        recipient: mailbox,
        count: 1,
      });
  }
  return (
    <section
      className="storage-view padded-view"
      aria-label="Live storage inspector"
    >
      <div className="storage-toolbar">
        <div>
          <p>Live Java memory · updates every 3 seconds · cleared on restart</p>
        </div>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => void refresh()}
        >
          Refresh storage
        </Button>
      </div>
      <div className="storage-filter">
        <Input
          aria-label="Filter storage"
          placeholder="Filter by user, key, message or signature…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <Badge variant="outline">
          {users.length} users · {messages.length} messages
        </Badge>
      </div>
      <p className="storage-mobile-hint">Swipe tables for more columns.</p>
      <p className="storage-update" role="status">
        {snapshot
          ? `Last updated ${snapshot.updated.toLocaleTimeString()}`
          : "Loading storage…"}
      </p>
      {error && (
        <Alert variant="destructive">
          <AlertTitle>Storage refresh failed</AlertTitle>
          <AlertDescription>
            {error}
            {snapshot
              ? " Showing the last successful snapshot."
              : " No storage snapshot is available."}
          </AlertDescription>
        </Alert>
      )}
      <section aria-labelledby="storage-users-title">
        <h3 id="storage-users-title">Users & keys</h3>
        <p>
          Public keys are visible. Private keys require an explicit reveal and
          stay only in this view’s memory.
        </p>
        <Table>
          <TableCaption>
            Demo user store joined to the server’s trusted public-key directory.
            This is not a persistent database.
          </TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>User / key owner</TableHead>
              <TableHead>Public key · X.509</TableHead>
              <TableHead>Server trust</TableHead>
              <TableHead>Private key · PKCS#8</TableHead>
              <TableHead>Inbox</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {users
              .filter((user) => matches(user.name, user.publicKey))
              .map((user) => {
                const revealed =
                  keys[user.name]?.publicKey === user.publicKey
                    ? keys[user.name]
                    : undefined;
                return (
                  <TableRow key={user.name}>
                    <TableCell>
                      <strong>{user.name}</strong>
                    </TableCell>
                    <TableCell>
                      <code>{user.publicKey}</code>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">
                        {user.trusted ? "Trusted" : "Untrusted"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {revealed ? (
                        <>
                          <code>{revealed.privateKey}</code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              setKeys((previous) => {
                                const next = { ...previous };
                                delete next[user.name];
                                return next;
                              })
                            }
                          >
                            Hide {user.name} private key
                          </Button>
                        </>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={keyBusy[user.name]}
                          onClick={() => void revealKey(user)}
                        >
                          Reveal {user.name} private key
                        </Button>
                      )}
                    </TableCell>
                    <TableCell>
                      {
                        messages.filter(
                          (message) => message.mailbox === user.name,
                        ).length
                      }
                    </TableCell>
                  </TableRow>
                );
              })}
          </TableBody>
        </Table>
        {snapshot &&
          !users.filter((user) => matches(user.name, user.publicKey))
            .length && <p>No matching users.</p>}
      </section>
      <section aria-labelledby="storage-connections-title">
        <h3 id="storage-connections-title">Connections</h3>
        <p>
          Observed sender → recipient links, counted from inbox records. A link
          shows stored deliveries, not a fresh signature check.
        </p>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Sender → key owner</TableHead>
              <TableHead>Recipient → inbox owner</TableHead>
              <TableHead>Stored deliveries</TableHead>
              <TableHead>Sender’s directory key</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {[...connections.values()]
              .filter((entry) => matches(entry.sender, entry.recipient))
              .map((entry) => (
                <TableRow key={JSON.stringify([entry.sender, entry.recipient])}>
                  <TableCell>{entry.sender}</TableCell>
                  <TableCell>{entry.recipient}</TableCell>
                  <TableCell>{entry.count}</TableCell>
                  <TableCell>
                    <code>
                      {users.find((user) => user.name === entry.sender)
                        ?.publicKey ?? "No registered sender key"}
                    </code>
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
        {snapshot && !connections.size && <p>No stored connections yet.</p>}
      </section>
      <section aria-labelledby="storage-messages-title">
        <h3 id="storage-messages-title">Stored messages</h3>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Mailbox owner</TableHead>
              <TableHead>Claimed sender</TableHead>
              <TableHead>Signed recipient</TableHead>
              <TableHead>Plaintext content</TableHead>
              <TableHead>Replay nonce</TableHead>
              <TableHead>Signature · Base64</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {messages
              .filter(({ mailbox, packet }) =>
                matches(
                  mailbox,
                  packet.senderId,
                  packet.receiverId,
                  packet.message,
                  packet.signature,
                ),
              )
              .map(({ mailbox, packet }, index) => (
                <TableRow key={`${mailbox}:${index}`}>
                  <TableCell>{mailbox}</TableCell>
                  <TableCell>{packet.senderId}</TableCell>
                  <TableCell>{packet.receiverId}</TableCell>
                  <TableCell className="storage-message">
                    {packet.message}
                  </TableCell>
                  <TableCell>
                    <code>{packet.nonce || "Legacy package — no nonce"}</code>
                  </TableCell>
                  <TableCell>
                    <code>{packet.signature}</code>
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
        {snapshot && !messages.length && <p>No stored messages yet.</p>}
      </section>
      <p>
        Normal mail uses a server-wide trust flag. Recipient-specific trust
        mappings and captured replays belong to the isolated Tests lab.
      </p>
    </section>
  );
}
