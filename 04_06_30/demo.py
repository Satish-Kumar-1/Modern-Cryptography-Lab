#!/usr/bin/env python3
"""Guided live demo. Run:  python demo.py      (press Enter to advance each step)
Add --auto to run without pauses. Uses its own folder (demo_run/) and never touches your real keys."""
import os, shutil, subprocess, sys
from pathlib import Path

AUTO = "--auto" in sys.argv
HERE = Path(__file__).resolve().parent
W = HERE / "demo_run"
TOOL = [sys.executable, str(HERE / "sign_verify.py")]
os.environ["SIGN_PASSPHRASE"] = "demo-passphrase"
if os.name == "nt":
    os.system("")  # enable ANSI colors in Windows terminals

G, R, Y, C, B, D, X = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[1m", "\033[2m", "\033[0m"


def pause():
    if not AUTO:
        input(f"\n{D}   [Enter to continue]{X}")


def step(n, title, why):
    print(f"\n{C}{B}{'=' * 70}\n STEP {n}: {title}\n{'=' * 70}{X}")
    print(f"{Y}Why:{X} {why}\n")


def show_cmd(args):
    """The exact command a person would type, with paths shown relative to the project folder."""
    parts = ["python", "sign_verify.py"] + [str(a) for a in args]
    out = []
    for p in parts:
        p = p.replace(str(W), "demo_run")
        if " " in p:
            p = f'"{p}"'
        out.append(p)
    return " ".join(out)


def make_file(path, text, why):
    """Create a file and show the equivalent command a person would type."""
    path.write_text(text, encoding="utf-8")
    shown = str(path).replace(str(W), "demo_run").replace("\\", "/")
    print(f"{D}# {why}{X}")
    print(f"{B}PS> Set-Content {shown} \"{text.strip()}\"{X}")
    print(f"{B}PS> type {shown}{X}")
    print(f"{text.strip()}\n")


def run(args, label=""):
    if label.startswith("("):
        print(f"{D}# {label.strip('()')}{X}")
    print(f"{B}PS> {show_cmd(args)}{X}")
    p = subprocess.run(TOOL + args, capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip()
    color = G if p.returncode == 0 else R
    print(f"{color}{B}{out}{X}")
    print(f"{D}exit code: {p.returncode}   (0 = valid, 1 = invalid, 4 = untrusted key){X}")
    return p.returncode


if W.exists():
    shutil.rmtree(W)
(W / "keys").mkdir(parents=True)
(W / "pub").mkdir()
doc = W / "contract.txt"

print(f"{B}Ed25519 Digital Signature Document Verification{X}")
print("Idea: the PRIVATE key signs, the PUBLIC key verifies. Change one byte and verification fails.")
pause()

step(1, "The document", "This is the file we want to protect. Anyone could edit it, so we need proof of who wrote it and that it is unchanged.")
make_file(doc, "Pay Rahul Rs. 1,000 for the project.\n",
          "We make a small text file to act as the contract. Any text would do; this one has an amount so the tamper step is easy to see")
pause()

step(2, "Generate a key pair for the author", "Private key = secret, encrypted with a passphrase, stored away from the project. Public key = shared with everyone.")
run(["keygen", "--name", "author", "--key-dir", str(W / "keys"), "--pub-dir", str(W / "pub")],
    "sign_verify keygen --name author")
pause()

step(3, "Sign the document", "Signing uses the private key. The 64-byte signature is saved in a separate file.")
sig = W / "contract.sig"
run(["sign", "--key", str(W / "keys" / "author_private.pem"), "--doc", str(doc), "--sig", str(sig)],
    "sign_verify sign --doc contract.txt")
print(f"\nSignature file (base64): {sig.read_text().strip()[:60]}...")
pause()

pub = W / "pub" / "author_public.pem"
step(4, "Verify the genuine document", "Verification needs only the PUBLIC key, so anyone can check.")
run(["verify", "--doc", str(doc), "--sig", str(sig), "--pubkey", str(pub)], "sign_verify verify --doc contract.txt")
pause()

step(5, "Attack 1: tamper with the document", "Someone changes Rs. 1,000 to Rs. 10,000. The signature was made over the old bytes, so it must fail.")
forged = W / "contract_tampered.txt"
make_file(forged, "Pay Rahul Rs. 10,000 for the project.\n",
          "A copy of the contract with one change: 1,000 became 10,000. The signature file is NOT changed")
run(["verify", "--doc", str(forged), "--sig", str(sig), "--pubkey", str(pub)], "sign_verify verify --doc contract_tampered.txt")
pause()

step(6, "Attack 2: attacker substitutes their own key", "Mallory edits the document, signs it with HER key, and hands you her public key. Without a check, it looks valid.")
run(["keygen", "--name", "mallory", "--key-dir", str(W / "keys"), "--pub-dir", str(W / "pub")], "(attacker generates her own key)")
mdoc = W / "mallory_contract.txt"
make_file(mdoc, "Pay Mallory Rs. 50,000.\n", "The attacker writes her own fake contract")
msig = W / "mallory.sig"
run(["sign", "--key", str(W / "keys" / "mallory_private.pem"), "--doc", str(mdoc), "--sig", str(msig)], "(attacker signs her fake)")
mpub = W / "pub" / "mallory_public.pem"
print(f"\n{B}Naive check (trusts whatever key it is handed):{X}")
run(["verify", "--doc", str(mdoc), "--sig", str(msig), "--pubkey", str(mpub)], "sign_verify verify ... --pubkey mallory_public.pem")
print(f"\n{Y}Problem:{X} VALID only proves the signer held THAT key, not that the key belongs to the author.")
pause()

step(7, "The defence: pin the fingerprint", "We learn the author's real key fingerprint through a trusted channel (in person, phone call). The tool compares it BEFORE verifying.")
fp = (W / "pub" / "author_public.fingerprint").read_text().strip()
print(f"Trusted fingerprint of the author's key:\n  {fp}\n")
print(f"{B}Mallory's fake, with pinning:{X}")
run(["verify", "--doc", str(mdoc), "--sig", str(msig), "--pubkey", str(mpub), "--fingerprint", fp], "sign_verify verify ... --fingerprint <author's>")
print(f"\n{B}The real author's document, with pinning:{X}")
run(["verify", "--doc", str(doc), "--sig", str(sig), "--pubkey", str(pub), "--fingerprint", fp], "sign_verify verify ... --fingerprint <author's>")
pause()

print(f"\n{G}{B}SUMMARY{X}")
print(" - Valid document + right key      -> VALID")
print(" - Any changed byte                -> INVALID SIGNATURE")
print(" - Attacker's own key, no pinning  -> VALID (the danger)")
print(" - Attacker's own key, pinned      -> UNTRUSTED KEY (the fix)")
print("\nAll evidence for the full experiment set is in logs/ and screenshots/.")