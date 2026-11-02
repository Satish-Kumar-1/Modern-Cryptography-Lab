"""Interactive security experiments"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timedelta, timezone

from . import crypto, messages, store, ui


class Lab:
    def __init__(self, interactive: bool = True):
        self.interactive = interactive
        self.lines: list[str] = []
        self.outcomes: list[tuple[str, dict, bool]] = []  # (label, result, is_attack)

    # ---- output (printed with colour, stored plain for the log file)
    def say(self, text: str = "") -> None:
        ui.show(text)
        self.lines.append(text)

    def banner(self, n: int, title: str) -> None:
        self.say(f"\n{ui.rule('=')}\n EXPERIMENT {n} of 5: {title}\n{ui.rule('=')}")

    def kv(self, label: str, value) -> None:
        self.say(ui.fmt_kv(label, value, width=20))

    def verdict(self, label: str, res: dict) -> None:
        self.say(ui.fmt_kv(label, f"{ui.badge(res['valid'])} {res['reason']}", width=20))

    def why(self, text: str) -> None:
        self.say()
        self.say(ui.fmt_para(text, label="Why:" if not text.startswith("Count") else ""))

    # ---- input
    def ask(self, label: str, default: str) -> str:
        if not self.interactive:
            return default
        try:
            value = input(f"  > {label} [{default}]: ").strip()
        except EOFError:
            value = ""
        return value or default

    def pick_user(self, label: str, default: str, exclude: tuple[str, ...] = ()) -> str:
        while True:
            name = self.ask(label, default)
            canon = store.canonical_name(name)
            if canon is None:
                if not store.NAME_RE.match(name):
                    self.say("  Invalid name.")
                    if not self.interactive:
                        raise ValueError(name)
                    continue
                if self.ask(f"'{name}' does not exist. Create it? (y/n)", "y").lower() != "y":
                    continue
                self.say(f"  Created {name} (fingerprint {ui.short_fp(store.create_user(name))})")
                canon = name
            if canon in exclude:
                self.say(f"  Pick someone other than: {', '.join(exclude)}.")
                if not self.interactive:
                    raise ValueError(canon)
                continue
            return canon

    def record(self, label: str, result: dict, attack: bool) -> None:
        self.outcomes.append((label, result, attack))


def run_experiments(interactive: bool = True) -> str:
    lab = Lab(interactive)
    lab.say(ui.fmt_header("Security experiments"))
    lab.say("  Choose the roles (press Enter to accept the suggestion).\n")
    sender = lab.pick_user("Honest sender  ", "Alice")
    receiver = lab.pick_user("Honest receiver", "Bob", (sender,))
    attacker = lab.pick_user("Attacker       ", "Mallory", (sender, receiver))
    pins, trust = store.load_pins(), store.load_trust_store()

    # 1 ---------------------------------------------------------- modification
    lab.banner(1, "Message modification")
    text = lab.ask("Message to sign", "Meet at the library at 5pm")
    original = messages.create_signed_message(sender, receiver, text)
    good = messages.verify_message(original, reader=receiver, check_replay=False)
    lab.record("Control: untouched message", good, False)
    find = lab.ask("Text inside the message to change", max(text.split(), key=len))
    repl = lab.ask("Replace it with", find.upper() if find.upper() != find else find + "!")
    tampered = copy.deepcopy(original)
    tampered["body"] = text.replace(find, repl, 1) if find in text else text + repl
    bad = messages.verify_message(tampered, reader=receiver, check_replay=False)
    lab.record("Message modification", bad, True)
    lab.say()
    lab.kv("Original body", original["body"])
    lab.kv("Tampered body", tampered["body"])
    lab.kv("Signature", ui.clip(original["signature"], 48) + "  (unchanged)")
    lab.say()
    lab.verdict("Untouched message", good)
    lab.verdict("Tampered message", bad)
    lab.why("RSA-PSS signs a hash of the exact canonical bytes. Any changed character gives a "
            "different hash, so the old signature no longer verifies.")

    # 2 ---------------------------------------------------------- impersonation
    lab.banner(2, "Impersonation attempt")
    forged_text = lab.ask("What does the attacker write?", f"I am {sender}. Wire the funds.")
    forged = messages.create_signed_message(sender, receiver, forged_text, signer=attacker)
    imp = messages.verify_message(forged, reader=receiver, check_replay=False)
    lab.record("Impersonation", imp, True)
    own_ok = crypto.verify(store.trusted_public_key(attacker, trust),
                           base64.b64decode(forged["signature"]), messages.canonical_bytes(forged))
    lab.say()
    lab.kv("Attacker", f"{attacker} signs with their OWN private key")
    lab.kv("Claimed sender", f"{sender} (From field)")
    lab.kv("Body", forged["body"])
    lab.say()
    lab.verdict(f"{receiver} verifies", imp)
    lab.kv(f"Valid for {attacker}?", f"{own_ok}  (a real signature, but not {sender}'s)")
    lab.why(f"{attacker} cannot create a signature that verifies under {sender}'s public key "
            f"without {sender}'s private key.")

    # 3 ---------------------------------------------------------- key substitution
    lab.banner(3, "Public-key substitution")
    naive_trust = copy.deepcopy(trust)
    naive_trust[sender] = copy.deepcopy(trust[attacker])
    naive = messages.verify_message(forged, reader=receiver, check_replay=False,
                                    pin_fingerprints=False, trust=naive_trust)
    pinned = messages.verify_message(forged, reader=receiver, check_replay=False,
                                     pin_fingerprints=True, trust=naive_trust, pins=pins)
    lab.record("Key substitution, NO pinning", naive, True)
    lab.record("Key substitution, fingerprint pinning", pinned, True)
    on_file = crypto.fingerprint(store.trusted_public_key(sender, naive_trust))
    lab.say(ui.fmt_para(f"{attacker} replaces {sender}'s entry in {receiver}'s key directory "
                        f"with {attacker}'s public key."))
    lab.say()
    lab.kv(f"Pinned ({sender})", ui.short_fp(pins[sender]))
    lab.kv("Key now on file", ui.short_fp(on_file))
    lab.say()
    lab.verdict("Without pinning", naive)
    lab.verdict("With pinning", pinned)
    lab.say()
    lab.say(ui.fmt_para("(1) compare SHA-256 fingerprints out-of-band, (2) fetch keys over an "
                        "authenticated channel, (3) use CA-issued certificates, (4) alert when a "
                        "known key changes.", label="Countermeasures:"))

    # 4 ---------------------------------------------------------- confidentiality
    lab.banner(4, "Confidentiality analysis")
    secret = lab.ask("Secret message", "Secret: exam is postponed")
    plain = messages.create_signed_message(sender, receiver, secret)
    plain_res = messages.verify_message(plain, reader=receiver, check_replay=False)
    lab.record("Signed-only message", plain_res, False)
    enc = messages.create_signed_message(sender, receiver, secret, encrypt=True)
    ok, info = messages.try_decrypt_as(enc, attacker)
    enc_res = messages.verify_message(enc, reader=receiver, check_replay=False)
    lab.record("Signed + encrypted message", enc_res, False)
    flipped = copy.deepcopy(enc)
    mid = len(flipped["body"]) // 2
    flipped["body"] = flipped["body"][:mid] + ("A" if flipped["body"][mid] != "A" else "B") + flipped["body"][mid + 1:]
    flip_res = messages.verify_message(flipped, reader=receiver, check_replay=False)
    lab.record("Ciphertext tampering", flip_res, True)
    lab.say("\n  A) Signed only")
    lab.kv(f"{attacker} sees", plain["body"])
    lab.verdict("Signature", plain_res)
    lab.say(ui.fmt_para("Valid signature, yet the content is fully readable."))
    lab.say("\n  B) Signed + encrypted")
    lab.kv(f"{attacker} sees", ui.clip(enc["body"], 56))
    lab.kv(f"{attacker} decrypts", "SUCCESS (bad!)" if ok else "FAILED - not the recipient")
    lab.kv(f"{receiver} reads", repr(enc_res["plaintext"]))
    lab.verdict("1 flipped char", flip_res)
    lab.why("Signatures give authenticity and integrity; encryption gives confidentiality. A fresh "
            "AES-256-GCM key per message is wrapped with the recipient's RSA-OAEP key, and the "
            "signature covers the ciphertext and wrapped key.")

    # 5 ---------------------------------------------------------- replay
    lab.banner(5, "Replay attack")
    cmd = lab.ask("Message the attacker will record and replay", "Unlock the door once")
    first = messages.create_signed_message(sender, receiver, cmd)
    cache: set[str] = set()
    r1 = messages.verify_message(first, reader=receiver, seen=cache)
    r2 = messages.verify_message(copy.deepcopy(first), reader=receiver, seen=cache)
    lab.record("First delivery", r1, False)
    lab.record("Replay of same message", r2, True)
    try:
        hours = float(lab.ask("Age (hours) of a stale message to test", "48"))
    except ValueError:
        hours = 48.0
    old_ts = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    stale = messages.create_signed_message(sender, receiver, cmd, timestamp=old_ts)
    r3 = messages.verify_message(stale, reader=receiver, seen=set())
    lab.record("Stale (old timestamp) message", r3, True)
    lab.say()
    lab.kv("Message id", first["id"])
    lab.say()
    lab.verdict("First delivery", r1)
    lab.verdict("Second delivery", r2)
    lab.verdict("Stale message", r3)
    lab.why("The receiver remembers accepted message ids and enforces a timestamp window. "
            "Counters or nonces work the same way: reuse is detected.")

    # summary (derived from the actual results) ------------------------------
    lab.say(ui.fmt_header("Summary"))
    rows = []
    for label, res, attack in lab.outcomes:
        outcome = ("attack SUCCEEDED" if res["valid"] else "attack blocked") if attack \
            else ("accepted" if res["valid"] else "REJECTED")
        rows.append((label, outcome, res["stage"]))
    lab.say(ui.fmt_table(("Test", "Outcome", "Stage"), rows))

    text_out = "\n".join(lab.lines) + "\n"
    store.SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().isoformat(timespec="seconds")
    with (store.SAMPLES_DIR / "experiment_log.txt").open("a", encoding="utf-8") as handle:
        handle.write(f"\n{'#' * 72}\nSCRIPTED EXPERIMENT RUN {stamp} | sender={sender} "
                     f"receiver={receiver} attacker={attacker}\n{'#' * 72}\n{text_out}")
    (store.SAMPLES_DIR / "sample_signed_message.json").write_text(json.dumps(original, indent=2), encoding="utf-8")
    (store.SAMPLES_DIR / "sample_encrypted_message.json").write_text(json.dumps(enc, indent=2), encoding="utf-8")
    (store.SAMPLES_DIR / "public_keys.json").write_text(json.dumps(trust, indent=2), encoding="utf-8")
    return text_out