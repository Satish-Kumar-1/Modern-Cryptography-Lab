package com.mohnish.signedchat.lab;

import com.mohnish.signedchat.service.SignatureService;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Isolated, short-lived experiment state. Never changes the normal user registry. */
@Service
public class ExperimentService {
    public record Identity(String name, String publicKey, String privateKey, String fingerprint) {}
    public record Package(String messageId, String senderId, String receiverId, String message, String signature) {}
    public record Prepare(String senderId, String receiverId, String message) {}
    public record Sign(Package packet, String privateKey) {}
    public record Check(Package packet, String recipientId) {}
    public record Trust(String recipientId, String senderId, String publicKey) {}
    public record Delivery(Package packet, String recipientId, boolean replayProtection) {}
    public record Stored(String deliveryId, String recipientId, Package packet) {}
    public record Result(Boolean signatureValid, boolean trusted, boolean keyMatchesPinned,
                         boolean recipientMatches, boolean duplicate, boolean accepted,
                         String reason, String verificationKeyFingerprint, String pinnedKeyFingerprint,
                         String payload, String payloadBase64, String comparisonDigest) {}
    private static class Session {
        final Map<String, Identity> identities = new LinkedHashMap<>();
        final Map<String, String> trustedKeys = new HashMap<>();
        final List<Stored> inbox = new ArrayList<>();
        final Set<String> seen = new HashSet<>();
        final List<Map<String, Object>> events = new ArrayList<>();
    }
    private final SignatureService signatures;
    private final Map<String, Session> sessions = new LinkedHashMap<>();
    public ExperimentService(SignatureService signatures) { this.signatures = signatures; }
    private String index(String recipient, String sender) { return recipient + ":" + sender; }
    private void event(Session session, String action, Object detail) {
        session.events.add(Map.of("time", java.time.Instant.now().toString(), "action", action, "detail", detail));
        if (session.events.size() > 200) session.events.remove(0);
    }
    public synchronized Map<String, Object> create() throws GeneralSecurityException {
        // Bound memory even when this public classroom demonstration is repeatedly opened.
        if (sessions.size() >= 64) sessions.remove(sessions.keySet().iterator().next());
        String id = UUID.randomUUID().toString();
        Session session = new Session();
        for (String name : List.of("alice", "bob", "mallory")) {
            KeyPair pair = signatures.generateKeyPair();
            String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
            session.identities.put(name, new Identity(name, publicKey,
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()), fingerprint(publicKey)));
        }
        for (String recipient : session.identities.keySet()) {
            for (Identity identity : session.identities.values()) {
                if (!identity.name().equals("mallory"))
                    session.trustedKeys.put(index(recipient, identity.name()), identity.publicKey());
            }
        }
        sessions.put(id, session);
        event(session, "Created isolated lab", "Alice and Bob keys pinned; Mallory initially untrusted");
        return Map.of("sessionId", id, "identities", session.identities.values());
    }
    private Session session(String id) {
        Session session = sessions.get(id);
        if (session == null) throw new IllegalArgumentException("Lab expired or reset. Create a new lab.");
        return session;
    }
    private void validate(Session session, Package packet, String recipient) {
        if (packet == null || packet.messageId() == null || packet.messageId().isBlank() ||
            packet.message() == null || packet.signature() == null ||
            !session.identities.containsKey(packet.senderId()) ||
            !session.identities.containsKey(packet.receiverId()) ||
            !session.identities.containsKey(recipient))
            throw new IllegalArgumentException("Use a nonblank message ID, known lab identities, message and signature.");
        if (packet.message().length() > 10000 || packet.signature().length() > 2000 || packet.messageId().length() > 200)
            throw new IllegalArgumentException("Experiment package exceeds size limit.");
    }
    private String field(String value) { return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)); }
    private String payload(Package packet) {
        return "signedchat-lab-v1:" + field(packet.messageId()) + ":" + field(packet.senderId()) + ":" +
            field(packet.receiverId()) + ":" + field(packet.message());
    }
    private String fingerprint(String publicKey) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Base64.getDecoder().decode(publicKey)));
    }
    public synchronized Package prepare(String id, Prepare request) {
        Session session = session(id);
        Package packet = new Package(UUID.randomUUID().toString(), request.senderId(), request.receiverId(), request.message(), "");
        validate(session, packet, request.receiverId());
        event(session, "Prepared new message ID", packet);
        return packet;
    }
    public synchronized Package sign(String id, Sign request) throws GeneralSecurityException {
        Session session = session(id);
        if (request.packet() == null) throw new IllegalArgumentException("Prepare a package before signing.");
        validate(session, request.packet(), request.packet().receiverId());
        if (request.privateKey() == null || request.privateKey().length() > 4000)
            throw new IllegalArgumentException("Provide an Ed25519 PKCS8 private key in Base64.");
        PrivateKey key;
        try {
            key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(request.privateKey())));
        } catch (IllegalArgumentException | GeneralSecurityException error) {
            event(session, "Signing failed", "Invalid Ed25519 private key");
            throw new IllegalArgumentException("Signing failed: invalid Base64 / PKCS8 Ed25519 private key.");
        }
        Package packet = request.packet();
        byte[] signature = signatures.sign(payload(packet).getBytes(StandardCharsets.UTF_8), key);
        Package signed = new Package(packet.messageId(), packet.senderId(), packet.receiverId(), packet.message(), Base64.getEncoder().encodeToString(signature));
        event(session, "Signed current package", signed);
        return signed;
    }
    private Result inspect(Session session, Package packet, String recipient, boolean protect, boolean deliver) throws GeneralSecurityException {
        validate(session, packet, recipient);
        String encodedKey = session.trustedKeys.get(index(recipient, packet.senderId()));
        String pinned = session.identities.get(packet.senderId()).publicKey();
        boolean trusted = encodedKey != null;
        boolean valid = false;
        String reason = trusted ? "INVALID_SIGNATURE" : "NO_TRUSTED_KEY";
        if (trusted) {
            try {
                PublicKey key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
                valid = signatures.verify(payload(packet).getBytes(StandardCharsets.UTF_8), Base64.getDecoder().decode(packet.signature()), key);
            } catch (IllegalArgumentException | GeneralSecurityException error) { reason = "MALFORMED_SIGNATURE"; }
        }
        boolean matches = recipient.equals(packet.receiverId());
        String token = recipient + ":" + packet.senderId() + ":" + packet.messageId();
        boolean duplicate = session.seen.contains(token);
        boolean accepted = valid && matches && (!protect || !duplicate);
        if (valid) reason = !matches ? "WRONG_RECIPIENT" : protect && duplicate ? "DUPLICATE_MESSAGE_ID" : "ACCEPTED";
        if (deliver && accepted) {
            if (session.seen.size() >= 1000 && !duplicate) throw new IllegalArgumentException("Lab delivery limit reached. Reset the lab.");
            session.seen.add(token);
            session.inbox.add(new Stored(UUID.randomUUID().toString(), recipient, packet));
            if (session.inbox.size() > 200) session.inbox.remove(0);
        }
        String payload = payload(packet);
        Result result = new Result(trusted ? valid : null, trusted, Objects.equals(encodedKey, pinned), matches, duplicate, accepted,
            reason, trusted ? fingerprint(encodedKey) : "", fingerprint(pinned), payload, field(payload),
            HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload.getBytes(StandardCharsets.UTF_8))));
        event(session, deliver ? "Delivery decision" : "Verification only (not delivered)", Map.of("packet", packet, "result", result));
        return result;
    }
    public synchronized Result verify(String id, Check request) throws GeneralSecurityException {
        return inspect(session(id), request.packet(), request.recipientId(), false, false);
    }
    public synchronized Result deliver(String id, Delivery request) throws GeneralSecurityException {
        return inspect(session(id), request.packet(), request.recipientId(), request.replayProtection(), true);
    }
    public synchronized void trust(String id, Trust request) throws GeneralSecurityException {
        Session session = session(id);
        if (!session.identities.containsKey(request.recipientId()) || !session.identities.containsKey(request.senderId()))
            throw new IllegalArgumentException("Unknown lab identity");
        String key = request.publicKey();
        if (key != null && !key.isBlank()) {
            if (key.length() > 4000) throw new IllegalArgumentException("Public key too long");
            try { KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(key))); }
            catch (IllegalArgumentException | GeneralSecurityException error) { throw new IllegalArgumentException("Invalid Ed25519 public key"); }
            session.trustedKeys.put(index(request.recipientId(), request.senderId()), key);
        } else session.trustedKeys.remove(index(request.recipientId(), request.senderId()));
        event(session, "Changed recipient trust mapping", Map.of("recipient", request.recipientId(), "sender", request.senderId(), "publicKey", key == null ? "" : key));
    }
    public synchronized void edit(String id, String deliveryId, Package packet) {
        Session session = session(id);
        for (int i = 0; i < session.inbox.size(); i++) {
            Stored stored = session.inbox.get(i);
            if (stored.deliveryId().equals(deliveryId)) {
                validate(session, packet, stored.recipientId());
                session.inbox.set(i, new Stored(deliveryId, stored.recipientId(), packet));
                event(session, "Edited stored package without signing", Map.of("before", stored.packet(), "after", packet));
                return;
            }
        }
        throw new IllegalArgumentException("Unknown delivery record");
    }
    public synchronized Map<String, Object> state(String id) {
        Session session = session(id);
        return Map.of("inbox", List.copyOf(session.inbox), "trustedKeys", Map.copyOf(session.trustedKeys), "events", List.copyOf(session.events));
    }
    public synchronized void delete(String id) { sessions.remove(id); }
}
