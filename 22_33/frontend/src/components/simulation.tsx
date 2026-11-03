import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import type { Api, SignedMessage, User } from "@/lib/api.js";
import { reconcileConversation } from "@/lib/api.js";
import { errorMessage, useTask } from "@/lib/use-task";
import { Empty, MessageDetails } from "./message-details";

export function Simulation({
  api,
  users,
  onDelivered,
}: {
  api: Api;
  users: User[];
  onDelivered: () => void;
}) {
  const [pair, setPair] = useState<[string, string]>([
    users[0]?.name || "",
    users[1]?.name || "",
  ]);
  const [messages, setMessages] = useState<SignedMessage[]>([]),
    [drafts, setDrafts] = useState(["", ""]),
    [notice, setNotice] = useState(""),
    [tab, setTab] = useState(0);
  const { busy, run } = useTask();
  const load = useCallback(
    async (current: () => boolean) => {
      const lists = await Promise.all(
        pair.map((name) => (name ? api.getInbox(name) : Promise.resolve([]))),
      );
      if (current())
        setMessages((previous) =>
          reconcileConversation(previous, lists.flat()),
        );
    },
    [api, pair],
  );
  useEffect(() => {
    let active = true;
    queueMicrotask(() => {
      if (active) void run(load, (error) => setNotice(errorMessage(error)));
    });
    return () => {
      active = false;
    };
  }, [load, run]);
  const choose = (index: number, value: string) => {
    setPair((previous) =>
      index === 0 ? [value, previous[1]] : [previous[0], value],
    );
    setMessages([]);
    setDrafts(["", ""]);
    setNotice("");
  };
  return (
    <section className="padded-view">
      <div className="section-intro">
        <h2>Two identities. Both sides of the exchange.</h2>
        <p>
          Sign as either demo user without changing your workspace identity.
        </p>
      </div>
      <div className="identity-selectors">
        {[0, 1].map((i) => (
          <label key={i}>
            {i ? "Right user" : "Left user"}
            <select
              aria-label={i ? "Right user" : "Left user"}
              value={pair[i]}
              onChange={(event) => choose(i, event.target.value)}
              disabled={busy}
            >
              <option value="">Choose a user</option>
              {users.map((user) => (
                <option key={user.name} disabled={user.name === pair[1 - i]}>
                  {user.name}
                </option>
              ))}
            </select>
          </label>
        ))}
      </div>
      <div className="mobile-tabs">
        {pair.map((name, i) => (
          <button key={i} aria-pressed={tab === i} onClick={() => setTab(i)}>
            {name || (i ? "Right user" : "Left user")}
          </button>
        ))}
      </div>
      <div className={"chat-grid " + (tab ? "show-bob" : "show-alice")}>
        {pair.map((name, i) => (
          <section className={"chat-panel " + (i ? "bob" : "alice")} key={i}>
            <div className="chat-heading">
              <div className="avatar">{name[0] || "?"}</div>
              <div>
                <h2>{name || "Choose a user"}</h2>
                <p>To {pair[1 - i] || "another identity"}</p>
              </div>
            </div>
            <div className="trust-strip">
              {users.find((user) => user.name === name)?.trusted
                ? "✓ Server-trusted key"
                : "Untrusted or missing signing key"}
            </div>
            <div className="messages" role="log">
              {messages
                .filter(
                  (message) =>
                    (message.senderId === name &&
                      message.receiverId === pair[1 - i]) ||
                    (message.senderId === pair[1 - i] &&
                      message.receiverId === name),
                )
                .map((message, index) => (
                  <article
                    className={
                      "message " +
                      (message.senderId === name ? "outgoing" : "incoming")
                    }
                    key={index}
                  >
                    <div className="message-sender">{message.senderId}</div>
                    <p>{message.message}</p>
                    <div className="verified">✓ Accepted by backend</div>
                    <MessageDetails message={message} />
                  </article>
                ))}
              {!messages.length && (
                <Empty
                  title="Start a signed exchange"
                  text="Choose two registered users and send from either identity."
                />
              )}
            </div>
            <form
              className="simulation-composer"
              onSubmit={(event) => {
                event.preventDefault();
                setNotice("");
                void run(
                  async (current) => {
                    const result = await api.send({
                      sender: name,
                      recipient: pair[1 - i],
                      content: drafts[i],
                    });
                    if (!current()) return;
                    if (!result.delivered) {
                      setNotice("Backend rejected delivery.");
                      return;
                    }
                    setDrafts((previous) =>
                      previous.map((value, index) =>
                        index === i ? "" : value,
                      ),
                    );
                    setNotice("Signed and delivered.");
                    await load(current);
                    if (current()) onDelivered();
                  },
                  (error) => setNotice(errorMessage(error)),
                );
              }}
            >
              <label className="sr-only" htmlFor={"simulation-message-" + i}>
                Message from {name || "left user"} to{" "}
                {pair[1 - i] || "right user"}
              </label>
              <Textarea
                id={"simulation-message-" + i}
                rows={2}
                value={drafts[i]}
                disabled={busy || !name || !pair[1 - i]}
                onChange={(event) =>
                  setDrafts((previous) =>
                    previous.map((value, index) =>
                      index === i ? event.target.value : value,
                    ),
                  )
                }
                placeholder={"Message " + (pair[1 - i] || "recipient") + "…"}
              />
              <Button
                type="submit"
                disabled={busy || !name || !pair[1 - i] || !drafts[i].trim()}
              >
                Sign & send
              </Button>
            </form>
          </section>
        ))}
      </div>
      <p className="notice" role="status">
        {notice}
      </p>
    </section>
  );
}
