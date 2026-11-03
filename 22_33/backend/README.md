# Messaging using Digital Signatures

A Spring Boot REST API for a small signed-messaging system. Every message is signed
with the sender's **Ed25519** private key and verified against a trusted public-key
store before it reaches the recipient's inbox. Unsigned, tampered, mis-addressed or
unknown-sender messages are rejected.

The cryptographic core (`model`, `service`, `encoding`, `store`) is plain Java with no
Spring dependency; the `api` and `config` packages wrap it in HTTP endpoints.

## How it works

1. `POST /api/users` creates a user. The server generates an Ed25519 key pair, keeps the
   private key, and registers the public key in the trusted key store.
2. Sending a message signs `base64(sender):base64(recipient):base64(content)` with the
   sender's private key.
3. On receipt the server looks up the sender's trusted public key, verifies the signature,
   checks the recipient matches, and only then appends the message to the inbox.

## Requirements

- JDK 21+
- No Maven install needed (the Maven Wrapper is included)

## Run

```bash
./mvnw spring-boot:run     # starts on http://localhost:8080
./mvnw test                # runs the API tests
```

## Endpoints

Base URL: `http://localhost:8080`. All bodies are JSON.

| Method | Path                       | Description                                              | Success                |
| ------ | -------------------------- | -------------------------------------------------------- | ---------------------- |
| POST   | `/api/users`               | Create a user and generate their key pair                | `201 Created`          |
| GET    | `/api/users`               | List all users and their public keys                     | `200 OK`               |
| GET    | `/api/users/{name}`        | Get one user                                             | `200 OK`               |
| GET    | `/api/users/{username}/keys` | Retrieve both server-held demo keys by username          | `200 OK`               |
| POST   | `/api/messages/sign`       | Sign a message with the sender's key (no delivery)       | `200 OK`               |
| POST   | `/api/messages`            | Sign a message **and** deliver it to the recipient       | `201 Created`          |
| POST   | `/api/users/{name}/inbox`  | Verify an already-signed message and deliver it          | `201 Created`          |
| GET    | `/api/users/{name}/inbox`  | List the messages accepted into a user's inbox           | `200 OK`               |

### `POST /api/users`

```json
{ "name": "Alice", "trusted": true }
```

`trusted` is optional (default `true`). With `"trusted": false` the user can sign messages
but their public key is not in the trusted store, so every message from them is rejected —
handy for simulating an attacker.

Creation response: `{ "name": "Alice", "publicKey": "<base64 X.509 key>", "privateKey": "<base64 PKCS#8 key>", "trusted": true }`

Creation and `GET /api/users/{username}/keys` return both keys with `Cache-Control: no-store`. The latter returns the existing pair, not a newly generated one, with the same response fields; unknown users return 404. Ordinary user list and lookup responses remain public-only. The server retains keys for signing.

The key lookup is deliberately unauthenticated for this classroom demo: anyone who knows a registered username can retrieve its private key. It does not prove user ownership and must not hold real secrets. Enter a username on Home to open the dedicated Key Vault (Page 1), or create a new identity if none exists. Continue to the mail workspace or log out to clear the displayed keys. Demo keys can be retrieved again through the header's Key Vault action.

### `POST /api/messages/sign`

```json
{ "sender": "Alice", "recipient": "Bob", "content": "Hello Bob!" }
```

Response (a signed message; `signature` is Base64):

```json
{ "message": "Hello Bob!", "signature": "oGqQ...DA==", "senderId": "Alice", "receiverId": "Bob" }
```

### `POST /api/messages`

Same request as `/sign`. Signs, then delivers to the recipient (who must exist).

```json
{ "message": { "message": "Hello Bob!", "signature": "oGqQ...DA==", "senderId": "Alice", "receiverId": "Bob" },
  "delivered": true }
```

Returns `422 Unprocessable Entity` with `"delivered": false` if verification fails
(e.g. the sender is untrusted).

### `POST /api/users/{name}/inbox`

Body is a signed message, as returned by `/sign`. `{name}` is the receiving user.

```json
{ "message": "Hello Bob!", "signature": "oGqQ...DA==", "senderId": "Alice", "receiverId": "Bob" }
```

- `201 Created` + `{ "accepted": true }`: signature valid, message stored.
- `422 Unprocessable Entity` + `{ "accepted": false }`: rejected (bad or tampered
  signature, unknown sender, or `receiverId` ≠ `{name}`).

### `GET /api/users/{name}/inbox`

Returns an array of signed messages in the same shape as above.

### Errors

Errors use [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem-detail JSON.

| Status | When                                                          |
| ------ | ------------------------------------------------------------- |
| 400    | Validation failure (blank name/ids, null content), malformed JSON, signature not valid Base64 |
| 404    | Unknown user                                                  |
| 409    | User name already exists                                      |
| 422    | Signature verification / delivery rejected                    |

## Example session

```bash
H='Content-Type: application/json'
curl -XPOST localhost:8080/api/users -H "$H" -d '{"name":"Alice"}'
curl -XPOST localhost:8080/api/users -H "$H" -d '{"name":"Bob"}'
curl -XPOST localhost:8080/api/users -H "$H" -d '{"name":"Mallory","trusted":false}'

# accepted (201)
curl -XPOST localhost:8080/api/messages -H "$H" \
  -d '{"sender":"Alice","recipient":"Bob","content":"Hello Bob!"}'

# rejected: Mallory's key is not trusted (422)
curl -XPOST localhost:8080/api/messages -H "$H" \
  -d '{"sender":"Mallory","recipient":"Bob","content":"Hi"}'

curl localhost:8080/api/users/Bob/inbox   # only Alice's message
```

To see tamper detection, call `/api/messages/sign`, edit the `message` field of the
response, and POST it to `/api/users/Bob/inbox`: you get `422`.

## Project layout

```
src/main/java/com/mohnish/signedchat/
├── model/      ChatUser, SignedMessage
├── service/    SignatureService (Ed25519), MessagingService, UserService
├── encoding/   PayloadEncoder
├── store/      TrustedKeyStore
├── api/        REST controllers, DTOs, error handling
└── config/     Spring wiring for the core classes
```

## Known limitations

The core signing/verification logic is unchanged from the original console version, and
the API inherits its behaviour:

- **No replay protection.** Resubmitting the same signed message is accepted again and
  appears twice in the inbox. A fix would be to sign a unique message ID and reject
  repeats.
- **In-memory only.** Users, keys and inboxes are lost on restart.
- **Server holds private keys.** This is a demo of the signing flow, not a production
  key-management design. There is no authentication on the endpoints.
- `MessagingService` stores inboxes in a plain `HashMap`, which is not thread-safe under
  concurrent requests.
