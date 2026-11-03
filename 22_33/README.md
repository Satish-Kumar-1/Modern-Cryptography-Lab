# SignedChat — messaging with digital signatures

A Java/Spring Boot Ed25519 backend with a React + Vite + TypeScript frontend. Tailwind CSS v4, shadcn/ui, and Kokonut UI provide the obsidian dark interface.

```text
backend/           Java API, Maven wrapper, source and tests
frontend/src/      React components and typed API/math imports
frontend/legacy/   Archived vanilla UI and its tests, for reference
Dockerfile         Node frontend build → Java build → Java-only runtime
render.yaml        Existing Render web service configuration
```

## Run locally

Install JDK 21+ and Node.js 22.12+ (Node 24 recommended).

```powershell
# Terminal 1
cd backend
.\mvnw.cmd spring-boot:run

# Terminal 2, starting at repository root
cd frontend
npm.cmd ci
npm.cmd run dev
```

Open http://127.0.0.1:5173. Vite proxies API requests to http://127.0.0.1:8080. Use `npm.cmd` on Windows if PowerShell blocks npm.ps1. On macOS/Linux, use `./mvnw` and `npm` instead.

Enter a username on Home. Existing users open the Key Vault; unknown names go through creation first. Inspect/copy the demo keys, then continue to the resizable Inbox, Compose/public-key search, user simulation, signing math, or the six-experiment Attack Lab. Logout clears the in-memory identity and React workspace state.

The username flow is not authentication. The backend deliberately allows retrieving demo private keys by username; use classroom keys only.

## Checks and production build

From frontend/:

```powershell
npm.cmd test
npm.cmd run lint
npm.cmd run build
npm.cmd run preview
```

Tests cover React identity/mail flows, stale-response logout handling, imported REST/math helpers, and the original Ed25519 vectors in math.test.cjs. The build type-checks the application and produces frontend/dist/.

From backend/, run `.\mvnw.cmd test`.

See [frontend/README.md](frontend/README.md) for architecture, registry setup, named imports, legacy references, proxy configuration, and testing. See [backend/README.md](backend/README.md) for API schemas and security behavior.

## Hosting

The root Dockerfile builds frontend/dist/ with Node, embeds it in Spring Boot's static resources, runs the Java tests, and packages the app. The runtime remains Java-only; frontend source, legacy files, and node_modules are not served.

Existing public application: https://signedchat-backend.onrender.com

Frontend and API share that origin. The Java app uses the hosting provider's PORT. Public Git repository URL services on Render require manual deploys after pushing; inspect existing deployments before triggering one.

The prototype stores users, keys, and inboxes only in memory. Restarting or redeploying resets them. Render's free service can sleep, so first requests may be slow. Messages are plaintext, normal mail rejects reused signed nonces, and public-key trust is a demo server flag. Signing math uses disposable example keys; real messaging uses established Java cryptography.

## Manual security experiments

Open a demo identity, continue to Mail Workspace, and choose **Tests** in the left navigation.
User information remains in the sidebar. Create an isolated lab; Alice, Bob, and Mallory are
fresh temporary identities, separate from normal mail. The seven experiment selectors provide
instructions, not automatic pass/fail scripts.

1. Prepare a message (creates a unique ID), then sign the current package with the selected key.
2. Inspect the signed original. Edit any package field without signing again to test tampering.
3. Verify without delivery, or deliver and inspect the backend decision and recipient inbox.
4. Capture a signed or received package; **Deliver again without re-signing** submits an immutable
   copy with the same ID and signature. With replay protection off, duplicates are accepted;
   with it on, a previously accepted ID is rejected. Preparing a new identical-text message
   creates a different signed ID, so intentional repeats are allowed.
5. For impersonation, claim Alice while signing with Mallory. For key substitution, apply
   Mallory's public key under Alice in Bob's directory, then verify again. A valid result with
   a mismatched pinned fingerprint illustrates why unauthenticated key distribution is unsafe.
6. Select a received record to edit stored text without re-signing, then verify that record.
7. Export the evidence log for the report. Reset deletes the old lab and generates fresh keys.

The lab's versioned signed payload is `signedchat-lab-v1:` followed by colon-separated Base64
UTF-8 fields in this exact order: message ID, sender ID, recipient ID, content. Ed25519 signs
those payload bytes directly. The displayed SHA-256 digest is only a comparison aid.
Normal messaging retains its existing three-field envelope for compatibility; replay protection
and recipient-specific editable trust maps are currently lab-only. Lab records are not normal
mailbox records. Neither interface encrypts message content. No production authentication or
persistent database is implied by this classroom prototype. Lab key pins are generated locally
for demonstration; a real system needs an independent authenticated trust-establishment process.

Every action returns actual Java results. Missing trust reports signature verification as not
checked; signature validity, key-pin match, recipient match, duplicate detection, and acceptance
are distinct. Verification-only does not store a message. Transport failures are errors, never
successful attack rejection. Logs omit private keys, but contain message text and public keys.
Labs are bounded, in memory, reset on restart, and may expire after many new labs are created.

For a repeatable real-HTTP check against your running backend:

```bash
python3 scripts/verify-lab.py http://localhost:8080
```

This creates and deletes only its own temporary lab, exercises all seven experiments, and exits
with an error if an observed outcome differs. It requires Python 3, with no third-party packages.
GitHub Actions runs the Java 21 backend suite and frontend build, tests, and lint on pushes.

## Normal-mail replay protection (v2)

Each signing operation creates a fresh 32-byte SecureRandom nonce, encoded as Base64.
The exact signed UTF-8 payload is `signedchat-v2:` followed by Base64 UTF-8 fields
in this order: nonce, sender ID, recipient ID, content, separated by colons.
The nonce is returned with the message and is itself authenticated by Ed25519.
The recipient verifies the signature before atomically recording the nonce and
storing the message. Reusing an accepted nonce is rejected; changing a captured
nonce invalidates its signature. Newly signing identical text creates a new nonce
and is accepted. Packages without a nonce are rejected, with no legacy fallback.
Nonce history shares the prototype's in-memory lifetime; durable/multi-instance
deployments require a shared persistent unique constraint. Nonces stop duplicate
delivery, not delayed first delivery or message-content disclosure.
The isolated lab still uses its signed unique message ID as its replay token and
retains its protection toggle to demonstrate the vulnerable case.
