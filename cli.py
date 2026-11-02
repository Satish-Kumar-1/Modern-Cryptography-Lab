"""Interactive multi-user messaging prototype with an attacker lab"""

from __future__ import annotations

import copy
import sys

from . import crypto, experiments, messages, store
from .ui import (badge, clip, fmt_header, fmt_kv, fmt_para, fmt_section, fmt_table,
                 fmt_ts, rule, short_fp, show)


def _prompt(label: str) -> str:
    try:
        return input(label).strip()
    except EOFError:
        raise SystemExit(0)


def _required(label: str) -> str:
    while True:
        value = _prompt(f"  > {label}: ")
        if value:
            return value
        print("    Please type something.")


def _yes(label: str) -> bool:
    return _prompt(f"  > {label} [y/N]: ").lower() in ("y", "yes")


def choose_user(label: str, exclude: tuple[str, ...] = ()) -> str | None:
    users = [u for u in store.list_users() if u not in exclude]
    if not users:
        show("  No suitable users. Create some with option 2.")
        return None
    for i, user in enumerate(users, 1):
        print(f"    {i}. {user}")
    while True:
        raw = _prompt(f"  > {label} (number or name, Enter to cancel): ")
        if not raw:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(users):
            return users[int(raw) - 1]
        canon = store.canonical_name(raw)
        if canon and canon not in exclude:
            return canon
        print("    Not a valid choice.")


def choose_message(owner: str) -> dict | None:
    inbox = store.read_inbox(owner)
    if not inbox:
        show(f"  {owner}'s inbox is empty. Send a message first.")
        return None
    print()
    for i, m in enumerate(inbox, 1):
        shown = "[encrypted]" if m["encrypted"] else clip(m["body"], 40)
        print(f"    {i}. {m['from']} -> {m['to']}   {shown}")
    raw = _prompt("  > Message number: ")
    if raw.isdigit() and 1 <= int(raw) <= len(inbox):
        return inbox[int(raw) - 1]
    print("    Invalid number.")
    return None


def report(result: dict, label: str | None = None, detail: str = "") -> None:
    if label:
        store.log_event(label, detail, result)
    print()
    show(fmt_kv("Result", f"{badge(result['valid'])} {result['reason']}", width=10))
    show(fmt_kv("Stage", result["stage"], width=10))
    if result.get("stored"):
        print(fmt_kv("Filed in", f"recipient's {result['stored']}", width=10))


# ------------------------------------------------------------------ user actions

def create_user_flow() -> str | None:
    name = _required("New user name")
    try:
        print("  Generating RSA-2048 key pair...")
        fp = store.create_user(name)
    except ValueError as exc:
        print(f"  {exc}")
        return None
    show(f"\n  Created user {name}")
    print(fmt_kv("Fingerprint", short_fp(fp), width=12))
    return name


def remove_user_flow(current: str) -> str | None:
    """Returns the user to continue as (or None if nobody is left)."""
    show(fmt_section("Remove a user"))
    victim = choose_user("User to remove")
    if not victim:
        return current
    print(f"\n  This permanently deletes {victim}'s keys, inbox and trust entry,")
    print(f"  and removes messages {victim} sent to others.")
    if not _yes(f"Remove {victim}?"):
        print("  Cancelled.")
        return current
    purged = store.remove_user(victim)
    show(f"\n  Removed {victim}. {purged} related message(s) purged from other mailboxes.")
    remaining = store.list_users()
    if not remaining:
        return None
    return current if current != victim else remaining[0]


def send_flow(current: str) -> None:
    show(fmt_section(f"Send a message as {current}"))
    print("  Recipient:")
    recipient = choose_user("Send to", exclude=(current,))
    if not recipient:
        return
    text = _required(f"Message to {recipient}")
    encrypt = _yes("Also encrypt (AES-GCM, key wrapped for the recipient)?")
    payload = messages.create_signed_message(current, recipient, text, encrypt=encrypt)
    print()
    print(fmt_kv("Message id", payload["id"], width=10))
    print(fmt_kv("Signature", clip(payload["signature"], 56), width=10))
    print(fmt_kv("Body", "ciphertext (hidden)" if encrypt else "plaintext (signature does not hide it)", width=10))
    store.save_sample(payload)
    kind = "encrypted" if encrypt else "plaintext"
    report(messages.deliver(payload), "SEND", f"{current} -> {recipient} ({kind}) id={payload['id']}")


def inbox_flow(current: str) -> None:
    inbox = store.read_inbox(current)
    show(fmt_header(f"Inbox of {current} ({len(inbox)} message{'s' if len(inbox) != 1 else ''})"))
    if not inbox:
        print("  (empty)")
    for i, payload in enumerate(inbox, 1):
        res = messages.verify_message(payload, reader=current, check_replay=False)
        kind = "encrypted" if payload["encrypted"] else "plaintext"
        print(f"\n  Message {i}   from {payload['from']}   {fmt_ts(payload['timestamp'])}   [{kind}]")
        print("  " + rule("-")[2:])
        status = "VALID (integrity + sender authenticated)" if res["valid"] else f"INVALID - {res['reason']}"
        show(fmt_kv("Signature", status, indent=4, width=10))
        if res["valid"]:
            print(fmt_kv("Message", res["plaintext"], indent=4, width=10))
    rejected = len(store.read_quarantine(current))
    if rejected:
        print(f"\n  Note: {rejected} message(s) were rejected on arrival (menu option 5).")


def quarantine_flow(current: str) -> None:
    items = store.read_quarantine(current)
    show(fmt_header(f"Rejected messages for {current} ({len(items)})"))
    if not items:
        print("  (none)")
    for i, item in enumerate(items, 1):
        p = item["payload"]
        print(f"\n  Rejected {i}   claims to be from {p.get('from')}")
        print("  " + rule("-")[2:])
        print(fmt_kv("Message id", p.get("id"), indent=4, width=12))
        print(fmt_kv("Body", clip(p.get("body"), 70), indent=4, width=12))
        show(fmt_kv("Why rejected", item["reason"], indent=4, width=12))


def keys_flow(current: str) -> None:
    pub = store.public_key_for(current)
    show(fmt_header(f"Keys and trust store ({current})"))
    print(fmt_kv("Fingerprint", crypto.fingerprint(pub), width=12))
    print(fmt_kv("Pinned", store.trusted_fingerprint(current), width=12))
    print("\n  Public key (PEM):\n")
    print("    " + crypto.public_key_pem(pub).strip().replace("\n", "\n    "))
    trust, pins = store.load_trust_store(), store.load_pins()
    rows = []
    for name in store.list_users():
        fp = crypto.fingerprint(crypto.public_key_from_pem(trust[name]["public_key_pem"]))
        rows.append((name, "OK" if fp == pins[name] else "MISMATCH", short_fp(fp)))
    show(fmt_section("Trust store vs. pinned fingerprints"))
    show(fmt_table(("User", "Status", "Fingerprint"), rows))
    claimed = _prompt("\n  > Optional: type a fingerprint received out-of-band to check it (Enter to skip): ")
    if claimed:
        hit = [n for n, f in pins.items() if f.lower() == claimed.lower()]
        print(f"  Matches the pinned key of {hit[0]}." if hit else "  No pinned identity has that fingerprint!")


# ------------------------------------------------------------------ attacker lab

LAB_MENU = """
  1  Intercept and tamper with a delivered message
  2  Impersonate a user (sign with the attacker's own key)
  3  Replay a recorded message
  4  Public-key substitution (in-memory, pinned vs. not pinned)
  5  Eavesdrop on someone's inbox
  6  Back
"""


def lab_menu() -> None:
    show(fmt_header("Attacker lab"))
    print(LAB_MENU)
    choice = _prompt("  > Attack [1-6]: ")
    print()
    if choice == "1":
        print("  Whose inbox do you intercept from?")
        owner = choose_user("Victim recipient")
        msg = choose_message(owner) if owner else None
        if not msg:
            return
        forged = copy.deepcopy(msg)
        if msg["encrypted"]:
            print("  The body is ciphertext; flipping one character of it.")
            b = forged["body"]
            forged["body"] = b[:5] + ("A" if b[5] != "A" else "B") + b[6:]
        else:
            forged["body"] = _required("Replacement body text")
        forged["id"] = msg["id"] + "-t"  # fresh id, so only the signature check can stop it
        report(messages.deliver(forged), "ATTACK tamper",
               f"altered copy of a message in {owner}'s inbox (id={msg['id']})")
    elif choice == "2":
        print("  Who is the attacker?")
        attacker = choose_user("Attacker")
        if not attacker:
            return
        print("\n  Who will they pretend to be?")
        victim = choose_user("Claimed sender", exclude=(attacker,))
        print("\n  Who receives the forged message?")
        target = choose_user("Recipient", exclude=(attacker, victim)) if victim else None
        if not (victim and target):
            return
        text = _required("Forged message text")
        report(messages.deliver(messages.create_signed_message(victim, target, text, signer=attacker)),
               "ATTACK impersonate", f"{attacker} posing as {victim} -> {target}")
    elif choice == "3":
        print("  Whose inbox did you record from?")
        owner = choose_user("Victim recipient")
        msg = choose_message(owner) if owner else None
        if msg:
            report(messages.deliver(copy.deepcopy(msg)), "ATTACK replay",
                   f"re-sent message id={msg['id']} to {owner}")
    elif choice == "4":
        print("  Who is the attacker?")
        attacker = choose_user("Attacker")
        print("\n  Whose key will be replaced?")
        victim = choose_user("Victim identity", exclude=(attacker,)) if attacker else None
        print("\n  Whose key directory is poisoned?")
        target = choose_user("Receiver", exclude=(attacker, victim)) if victim else None
        if not (attacker and victim and target):
            return
        text = _required("Forged message text")
        forged = messages.create_signed_message(victim, target, text, signer=attacker)
        trust = copy.deepcopy(store.load_trust_store())
        trust[victim] = copy.deepcopy(trust[attacker])
        show("\n  WITHOUT fingerprint pinning:")
        report(messages.verify_message(forged, reader=target, check_replay=False,
                                       pin_fingerprints=False, trust=trust),
               "ATTACK key-subst", f"{attacker} replaced {victim}'s key at {target}; NO pinning")
        show("\n  WITH fingerprint pinning:")
        report(messages.verify_message(forged, reader=target, check_replay=False, trust=trust),
               "ATTACK key-subst", f"same forged message; WITH fingerprint pinning")
    elif choice == "5":
        print("  Who is eavesdropping?")
        attacker = choose_user("Eavesdropper")
        print("\n  Whose inbox?")
        owner = choose_user("Victim") if attacker else None
        if not (attacker and owner):
            return
        inbox = store.read_inbox(owner)
        store.log_event("ATTACK eavesdrop", f"{attacker} read {owner}'s inbox ({len(inbox)} message(s))")
        if not inbox:
            print("  That inbox is empty.")
        for i, m in enumerate(inbox, 1):
            print(f"\n  Raw message {i}   from {m['from']}")
            print("  " + rule("-")[2:])
            print(fmt_kv("Body on disk", clip(m["body"], 70), indent=4, width=14))
            if m["encrypted"]:
                ok, _ = messages.try_decrypt_as(m, attacker)
                print(fmt_kv("Decrypt", "SUCCESS (bad!)" if ok else f"FAILED - {attacker} is not the recipient",
                             indent=4, width=14))
            else:
                print(fmt_kv("Readable?", "yes - signatures do not provide confidentiality", indent=4, width=14))


# ------------------------------------------------------------------ main menu

HELP = """
  1  Switch user              6  Attacker lab
  2  Create new user          7  Reset (delete all keys and data)
  3  Send a signed message    8  Quit
  4  My inbox                 k  My keys / trust store / fingerprints
  5  Rejected messages        r  Remove a user
  ?  Show this menu
"""


def menu() -> None:
    show(fmt_header("Secure Messaging - RSA-PSS prototype"))
    if not store.list_users():
        print("\n  No users yet. Create at least two (e.g. Alice and Bob) to begin.\n")
        while len(store.list_users()) < 2:
            create_user_flow()
            print()
    current = store.list_users()[0]
    print(HELP)
    while True:
        choice = _prompt(f"\n[{current}] choice > ").lower()
        print()
        if choice == "1":
            current = choose_user("Switch to") or current
        elif choice == "2":
            current = create_user_flow() or current
        elif choice == "3":
            send_flow(current)
        elif choice == "4":
            inbox_flow(current)
        elif choice == "5":
            quarantine_flow(current)
        elif choice == "r":
            current = remove_user_flow(current)
            if current is None:
                print("  No users left. Restarting setup.")
                return menu()
            if len(store.list_users()) < 2:
                print("  Note: fewer than two users remain. Create another with option 2 to send messages.")
        elif choice == "k":
            keys_flow(current)
        elif choice == "6":
            lab_menu()
        elif choice == "7":
            if _yes("This deletes ALL users, keys and mail. Continue?"):
                store.wipe_everything()
                print("  Wiped. Restarting setup.")
                return menu()
        elif choice == "8":
            print("  Bye.")
            return
        else:
            print(HELP)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["init"]:
        for name in argv[1:] or ["Alice", "Bob", "Mallory"]:
            try:
                print(f"{name}: {short_fp(store.create_user(name))}")
            except ValueError as exc:
                print(f"{name}: {exc}")
        return 0
    if argv[:1] == ["experiments"]:
        auto = "--auto" in argv
        if auto:
            for name in ("Alice", "Bob", "Mallory"):
                if not store.canonical_name(name):
                    store.create_user(name)
        experiments.run_experiments(interactive=not auto)
        return 0
    menu()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())