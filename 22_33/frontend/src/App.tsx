import { lazy, Suspense, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { createApi, ApiError } from "@/lib/api.js";
import type { User, UserKeys } from "@/lib/api.js";
import { errorMessage, useTask } from "@/lib/use-task";
import { IdentityEntry, KeyVault } from "@/components/identity-screens";

const api = createApi();
const MailWorkspace = lazy(() =>
  import("@/components/mail-workspace").then((module) => ({
    default: module.MailWorkspace,
  })),
);
type Screen = "home" | "create" | "vault" | "workspace";
function App() {
  const [screen, setScreen] = useState<Screen>("home"),
    [user, setUser] = useState<User | null>(null),
    [vault, setVault] = useState<UserKeys | null>(null);
  const [name, setName] = useState(""),
    [notice, setNotice] = useState("");
  const task = useTask();
  const { run: runTask } = task;
  const vaultName = screen === "vault" ? user?.name : undefined;
  useEffect(() => {
    if (!vaultName) return;
    let active = true;
    const timer = window.setInterval(() => {
      void runTask(
        async (current) => {
          const pair = await api.getUserKeys(vaultName);
          if (!active || !current()) return;
          setVault(pair);
          setUser({
            name: pair.name,
            publicKey: pair.publicKey,
            trusted: pair.trusted,
          });
          setNotice("");
        },
        (error) => {
          if (active) setNotice(errorMessage(error));
        },
      );
    }, 3000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [vaultName, runTask]);
  const open = (pair: UserKeys, showVault = false) => {
    if (!pair.name || !pair.publicKey || !pair.privateKey)
      throw new Error("The backend did not return a complete demo key pair.");
    setUser({
      name: pair.name,
      publicKey: pair.publicKey,
      trusted: pair.trusted,
    });
    setVault(showVault ? pair : null);
    setNotice("");
    setScreen(showVault ? "vault" : "workspace");
  };
  const logout = () => {
    task.cancel();
    setUser(null);
    setVault(null);
    setScreen("home");
    setName("");
    setNotice("");
  };
  const lookup = () => {
    if (!name.trim()) return;
    setNotice("");
    void task.run(
      async (current) => {
        try {
          const pair = await api.getUserKeys(name.trim());
          if (current()) open(pair);
        } catch (error) {
          if (!current()) return;
          if (error instanceof ApiError && error.status === 404)
            setScreen("create");
          else throw error;
        }
      },
      (error) => setNotice(errorMessage(error)),
    );
  };
  const create = async () => {
    let failure: unknown;
    if (!name.trim()) return;
    setNotice("");
    await task.run(
      async (current) => {
        try {
          const pair = await api.createUser({
            name: name.trim(),
            trusted: true,
          });
          if (current()) open(pair, true);
        } catch (error) {
          if (!current()) return;
          if (error instanceof ApiError && error.status === 409) {
            setScreen("home");
            setNotice(
              "That username was just registered. Continue to open the existing demo identity.",
            );
          } else throw error;
        }
      },
      (error) => {
        failure = error;
        setNotice(errorMessage(error));
      },
    );
    if (failure) throw failure;
  };
  return (
    <>
      {screen !== "workspace" && (
        <header className="app-header">
          <a
            href="#"
            className="brand"
            onClick={(event) => event.preventDefault()}
          >
            <span className="brand-mark">S</span>SignedChat
            <span className="brand-tag">LAB</span>
          </a>
          <div className="header-actions">
            <span className="environment">Ed25519 / demo environment</span>
            {user && (
              <>
                <span className="session-name">{user.name}</span>
                {screen !== "vault" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={task.busy}
                    onClick={() => {
                      setNotice("");
                      void task.run(
                        async (current) => {
                          const pair = await api.getUserKeys(user.name);
                          if (current()) open(pair, true);
                        },
                        (error) => setNotice(errorMessage(error)),
                      );
                    }}
                  >
                    Key vault
                  </Button>
                )}
                <Button variant="outline" size="sm" onClick={logout}>
                  Logout ↗
                </Button>
              </>
            )}
          </div>
        </header>
      )}
      {(screen === "home" || screen === "create") && (
        <IdentityEntry
          creating={screen === "create"}
          name={name}
          onName={setName}
          busy={task.busy}
          notice={notice}
          onLookup={lookup}
          onCreate={create}
          onBack={() => {
            setScreen("home");
            setNotice("");
          }}
        />
      )}
      {screen === "vault" && notice && (
        <p className="notice error" role="status">
          {notice}
        </p>
      )}
      {screen === "vault" && vault && (
        <KeyVault
          key={vault.name}
          pair={vault}
          onContinue={() => {
            setVault(null);
            setScreen("workspace");
          }}
        />
      )}
      {screen === "workspace" && user && (
        <>
          {notice && (
            <p className="notice error workspace-notice" role="status">
              {notice}
            </p>
          )}
          <Suspense
            fallback={
              <p className="padded-view" role="status">
                Opening Mail Workspace…
              </p>
            }
          >
            <MailWorkspace
              key={user.name}
              user={user}
              api={api}
              onLogout={logout}
              vaultBusy={task.busy}
              onVault={() => {
                setNotice("");
                void task.run(
                  async (current) => {
                    const pair = await api.getUserKeys(user.name);
                    if (current()) open(pair, true);
                  },
                  (error) => setNotice(errorMessage(error)),
                );
              }}
            />
          </Suspense>
        </>
      )}
    </>
  );
}
export default App;
