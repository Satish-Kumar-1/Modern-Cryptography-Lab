import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import type { Api, SignedMessage, User } from "@/lib/api.js";
import { errorMessage, useTask } from "@/lib/use-task";
import { Empty, MessageDetails, Timestamp } from "./message-details";
import { StorageView } from "./storage-view";

import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { AttackLab } from "./attack-lab";
const subscribeWidth = (change: () => void) => {
  window.addEventListener("resize", change);
  return () => window.removeEventListener("resize", change);
};
const isNarrow = () => window.innerWidth < 760;
type View = "inbox" | "compose" | "storage" | "attacks";
const titles: Record<View, string> = {
  inbox: "Inbox",
  compose: "Compose",
  storage: "Storage",
  attacks: "Tests",
};
export function MailWorkspace({
  user,
  api,
  onLogout,
  onVault,
  vaultBusy,
}: {
  user: User;
  api: Api;
  onLogout: () => void;
  onVault: () => void;
  vaultBusy: boolean;
}) {
  const narrow = useSyncExternalStore(subscribeWidth, isNarrow, () => false);
  const [view, setView] = useState<View>("inbox"),
    [users, setUsers] = useState<User[]>([]),
    [inbox, setInbox] = useState<SignedMessage[]>([]);
  const [directoryQuery, setDirectoryQuery] = useState(""),
    [inboxQuery, setInboxQuery] = useState(""),
    [index, setIndex] = useState<number | null>(null);
  const [recipient, setRecipient] = useState(""),
    [draft, setDraft] = useState(""),
    [notice, setNotice] = useState(""),
    [connection, setConnection] = useState<"checking" | "connected" | "error">(
      "checking",
    );
  const [copyNotice, setCopyNotice] = useState("");
  const [headerQuery, setHeaderQuery] = useState("");
  const { busy, run } = useTask();
  const load = useCallback(
    async (current: () => boolean) => {
      const [publicUsers, messages] = await Promise.all([
        api.listUsers(),
        api.getInbox(user.name),
      ]);
      if (current()) {
        setUsers(publicUsers.sort((a, b) => a.name.localeCompare(b.name)));
        setInbox(messages);
        setConnection("connected");
      }
    },
    [api, user.name],
  );
  const refresh = useCallback(() => {
    setNotice("");
    void run(load, (error) => {
      setConnection("error");
      setNotice(errorMessage(error));
    });
  }, [load, run]);
  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (active) refresh();
    });
    return () => {
      active = false;
    };
  }, [refresh]);
  useEffect(() => {
    if (view !== "inbox") return;
    let active = true;
    const timer = window.setInterval(() => {
      void run(
        (current) => load(() => active && current()),
        () => {
          if (active) setConnection("error");
        },
      );
    }, 3000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [view, load, run]);
  const matches = (filter: string) => {
    const name = filter.trim().toLocaleLowerCase(),
      key = name.replace(/\s/g, "");
    return users.filter(
      (entry) =>
        !name ||
        entry.name.toLocaleLowerCase().includes(name) ||
        entry.publicKey.toLocaleLowerCase().includes(key),
    );
  };
  const selected = users.find((entry) => entry.name === recipient),
    message = index === null ? undefined : inbox[index];
  const choose = (entry: User) => {
    setRecipient(entry.name);
    setView("compose");
    setNotice("");
    setCopyNotice("");
  };
  const directory = (filter: string) => (
    <>
      {matches(filter).map((entry) => (
        <button
          key={entry.name}
          className={
            "recipient-row " + (entry.name === recipient ? "selected" : "")
          }
          disabled={busy}
          onClick={() => choose(entry)}
        >
          <strong>{entry.name}</strong>
          <code>
            {entry.publicKey.slice(0, 18)}…{entry.publicKey.slice(-12)}
          </code>
        </button>
      ))}
      {!matches(filter).length && (
        <p className="hint">No matching registered users.</p>
      )}
    </>
  );
  return (
    <Tabs
      orientation="vertical"
      value={view}
      onValueChange={(value) => setView(value as View)}
      className="mail-shell"
    >
      <header className="mail-workspace-header">
        <div className="workspace-brand">
          <span className="brand-mark">S</span>
          <div>
            <strong>SignedChat</strong>
            <span>@{user.name}</span>
          </div>
        </div>
        <div className="workspace-search">
          <Input
            aria-label="Find users by username or public key"
            placeholder="Find a user or public key…"
            value={headerQuery}
            onChange={(event) => setHeaderQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") setHeaderQuery("");
              if (
                event.key === "Enter" &&
                headerQuery.trim() &&
                matches(headerQuery)[0]
              ) {
                choose(matches(headerQuery)[0]);
                setHeaderQuery("");
              }
            }}
          />
          {headerQuery.trim() && (
            <div
              className="search-results"
              role="listbox"
              aria-label="Matching users"
            >
              {matches(headerQuery).map((entry) => (
                <button
                  key={entry.name}
                  role="option"
                  aria-selected={false}
                  onClick={() => {
                    choose(entry);
                    setHeaderQuery("");
                  }}
                >
                  {entry.name}
                </button>
              ))}
              {!matches(headerQuery).length && <p>No matching users.</p>}
            </div>
          )}
        </div>
        <Badge variant="outline" className="backend-status">
          {connection === "checking"
            ? "Connecting…"
            : connection === "connected"
              ? "Backend connected"
              : "Backend request failed"}
        </Badge>
        <div className="header-actions">
          <Button
            variant="ghost"
            size="sm"
            onClick={onVault}
            disabled={vaultBusy}
          >
            Key vault
          </Button>
          <Button variant="outline" size="sm" onClick={onLogout}>
            Logout ↗
          </Button>
        </div>
      </header>
      <div className="workspace">
        <aside className="mail-sidebar">
          <TabsList
            className="dashboard-nav workspace-tab-list"
            aria-label="Mail navigation"
            variant="line"
          >
            {(Object.keys(titles) as View[]).map((name) => (
              <TabsTrigger
                key={name}
                value={name}
                className={view === name ? "nav-current" : ""}
              >
                {titles[name]}
                {name === "inbox" && (
                  <span className="count">{inbox.length}</span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
          <section
            className="lab-user-details"
            aria-label="Your identity and public key"
          >
            <h3>Your identity</h3>
            <strong>{user.name}</strong>
            <p>Trusted: {String(user.trusted)}</p>
            <pre>{user.publicKey}</pre>
          </section>
          <div className="sidebar-bottom">
            Ed25519 · signed mail
            <p>
              Backend verifies delivery.
              <br />
              Messages are not encrypted.
            </p>
          </div>
        </aside>
        <main className="mail-main">
          <div className="workspace-toolbar">
            <div>
              <h1>{titles[view]}</h1>
            </div>
            <div className="toolbar-actions">
              {view !== "storage" && view !== "attacks" && (
                <Button variant="outline" disabled={busy} onClick={refresh}>
                  ↻ Refresh
                </Button>
              )}
            </div>
          </div>
          {notice && (
            <p className="notice workspace-notice" role="status">
              {notice}
            </p>
          )}
          {view === "inbox" && (
            <TabsContent value="inbox">
              <section className="inbox-region" aria-label="Inbox">
                <ResizablePanelGroup
                  key={narrow ? "stacked" : "side-by-side"}
                  orientation={narrow ? "vertical" : "horizontal"}
                  className="inbox-panel-group"
                >
                  <ResizablePanel
                    id="message-list"
                    defaultSize="35%"
                    minSize={narrow ? "25%" : "22%"}
                  >
                    <div className="mail-list-column">
                      <div className="list-toolbar">
                        <label className="sr-only" htmlFor="inbox-search">
                          Search inbox
                        </label>
                        <Input
                          id="inbox-search"
                          type="search"
                          value={inboxQuery}
                          onChange={(event) =>
                            setInboxQuery(event.target.value)
                          }
                          placeholder="Search sender or message…"
                        />
                        <span>{inbox.length} received messages</span>
                      </div>
                      <ScrollArea className="mail-list-scroll">
                        <div className="mail-list" role="list">
                          {inbox
                            .map((entry, i) => ({ entry, i }))
                            .filter(({ entry }) =>
                              (entry.senderId + "\n" + entry.message)
                                .toLocaleLowerCase()
                                .includes(inboxQuery.toLocaleLowerCase()),
                            )
                            .map(({ entry, i }) => (
                              <div role="listitem" key={i}>
                                <button
                                  className={
                                    "mail-row " +
                                    (index === i ? "selected" : "")
                                  }
                                  aria-pressed={index === i}
                                  onClick={() => setIndex(i)}
                                >
                                  <strong>{entry.senderId}</strong>
                                  <p>{entry.message}</p>
                                  <span>✓ Accepted by backend</span>
                                </button>
                              </div>
                            ))}
                          {!inbox.length && (
                            <Empty
                              title="Your inbox is empty"
                              text="Received messages from every sender will appear here."
                            />
                          )}
                        </div>
                      </ScrollArea>
                    </div>
                  </ResizablePanel>
                  <ResizableHandle withHandle aria-label="Resize inbox panes" />
                  <ResizablePanel
                    id="reading-pane"
                    minSize={narrow ? "30%" : "35%"}
                  >
                    <ScrollArea className="reader-scroll">
                      <article
                        className="mail-reader"
                        aria-label="Selected message"
                      >
                        {message ? (
                          <>
                            <div className="reader-title">
                              <h2>Signed message</h2>
                              <Badge variant="secondary">
                                ✓ Backend accepted
                              </Badge>
                            </div>
                            <div className="reader-meta">
                              <p>
                                <b>FROM</b>
                                {message.senderId}
                              </p>
                              <p>
                                <b>TO</b>
                                {message.receiverId}
                              </p>
                              <p>
                                <b>TIME</b>
                                <Timestamp message={message} />
                              </p>
                            </div>
                            <div className="message-body">
                              {message.message}
                            </div>
                            <MessageDetails message={message} />
                            <Button
                              className="mt-6"
                              variant="outline"
                              onClick={() => {
                                const sender = users.find(
                                  (entry) => entry.name === message.senderId,
                                );
                                if (sender) {
                                  setDraft("");
                                  choose(sender);
                                }
                              }}
                            >
                              Reply →
                            </Button>
                          </>
                        ) : (
                          <Empty
                            title="Select a signed message"
                            text="Read its content and inspect its Ed25519 signature."
                          />
                        )}
                      </article>
                    </ScrollArea>
                  </ResizablePanel>
                </ResizablePanelGroup>
              </section>
            </TabsContent>
          )}
          {view === "compose" && (
            <TabsContent value="compose">
              <section className="padded-view">
                <div className="section-intro">
                  <h2>A message with your signature.</h2>
                  <p>
                    Find recipients by username or public key. The server signs
                    as your current demo identity.
                  </p>
                </div>
                <div className="compose-layout">
                  <section className="surface recipient-directory">
                    <label htmlFor="recipient-search">Find a recipient</label>
                    <Input
                      id="recipient-search"
                      type="search"
                      value={directoryQuery}
                      onChange={(event) =>
                        setDirectoryQuery(event.target.value)
                      }
                      placeholder="Username or public key…"
                    />
                    <div className="recipient-results">
                      {directory(directoryQuery)}
                    </div>
                  </section>
                  <form
                    className="surface compose-form"
                    aria-label="Compose signed message"
                    onSubmit={(event) => {
                      event.preventDefault();
                      if (!selected || !draft.trim()) return;
                      setNotice("");
                      void run(
                        async (current) => {
                          const result = await api.send({
                            sender: user.name,
                            recipient: selected.name,
                            content: draft,
                          });
                          if (!current()) return;
                          setConnection("connected");
                          if (!result.delivered) {
                            setNotice(
                              "The backend rejected this message. It was not delivered.",
                            );
                            return;
                          }
                          setDraft("");
                          setNotice(
                            "Signed and delivered to " + selected.name + ".",
                          );
                          try {
                            await load(current);
                          } catch {
                            if (current()) {
                              setConnection("error");
                              setNotice(
                                "Delivered. Refresh to synchronize your inbox.",
                              );
                            }
                          }
                        },
                        (error) => {
                          setConnection("error");
                          setNotice(errorMessage(error));
                        },
                      );
                    }}
                  >
                    <h2>
                      {selected
                        ? "Message to " + selected.name
                        : "New signed message"}
                    </h2>
                    <div className="compose-meta">
                      <span>FROM</span>
                      <strong>{user.name}</strong>
                    </div>
                    <div className="compose-meta">
                      <span>TO</span>
                      <strong>{selected?.name || "Select a recipient"}</strong>
                    </div>
                    {selected && (
                      <section
                        className="recipient-key"
                        aria-label="Recipient public key"
                      >
                        <div className="recipient-key-heading">
                          <span>PUBLIC KEY · X.509 / BASE64</span>
                          <Button
                            variant="ghost"
                            size="sm"
                            type="button"
                            onClick={async () => {
                              try {
                                await navigator.clipboard.writeText(
                                  selected.publicKey,
                                );
                                setCopyNotice("Copied public key");
                              } catch {
                                setCopyNotice("Copy unavailable");
                              }
                            }}
                          >
                            Copy public key
                          </Button>
                        </div>
                        <code>{selected.publicKey}</code>
                        <span role="status">{copyNotice}</span>
                      </section>
                    )}
                    <label htmlFor="compose-content">Message</label>
                    <Textarea
                      id="compose-content"
                      rows={10}
                      value={draft}
                      onChange={(event) => setDraft(event.target.value)}
                      disabled={busy}
                      placeholder="Write your message…"
                      required
                    />
                    <div className="compose-bottom">
                      <span>Ed25519 · signed by the backend</span>
                      <Button
                        type="submit"
                        disabled={busy || !selected || !draft.trim()}
                      >
                        Sign & Send →
                      </Button>
                    </div>
                  </form>
                </div>
              </section>
            </TabsContent>
          )}
          {view === "storage" && (
            <TabsContent value="storage">
              <StorageView api={api} />
            </TabsContent>
          )}
          {view === "attacks" && (
            <TabsContent value="attacks">
              <AttackLab api={api} />
            </TabsContent>
          )}
        </main>
      </div>
    </Tabs>
  );
}
