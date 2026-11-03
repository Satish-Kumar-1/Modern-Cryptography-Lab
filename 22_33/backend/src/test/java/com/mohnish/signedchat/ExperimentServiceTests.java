package com.mohnish.signedchat;

import com.mohnish.signedchat.lab.ExperimentService;
import com.mohnish.signedchat.lab.ExperimentService.*;
import com.mohnish.signedchat.lab.ExperimentService.Package;
import com.mohnish.signedchat.service.SignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ExperimentServiceTests {
    ExperimentService service;
    String session;
    Map<String, Identity> identities;
    @BeforeEach void setup() throws Exception {
        service = new ExperimentService(new SignatureService());
        Map<String, Object> created = service.create();
        session = (String) created.get("sessionId");
        identities = new HashMap<>();
        for (Object value : (Collection<?>) created.get("identities")) {
            Identity identity = (Identity) value;
            identities.put(identity.name(), identity);
        }
    }
    Package sign(String owner) throws Exception {
        Package draft = service.prepare(session, new Prepare("alice", "bob", "  Exact café\nmessage  "));
        return service.sign(session, new Sign(draft, identities.get(owner).privateKey()));
    }
    Result verify(Package packet) throws Exception { return service.verify(session, new Check(packet, "bob")); }
    Result deliver(Package packet, boolean protect) throws Exception { return service.deliver(session, new Delivery(packet, "bob", protect)); }
    @Test void exactContentAndMetadataAreAuthenticated() throws Exception {
        Package original = sign("alice");
        assertTrue(verify(original).signatureValid());
        assertFalse(verify(new Package(original.messageId(), "alice", "bob", "edited", original.signature())).signatureValid());
        assertFalse(verify(new Package("changed-id", "alice", "bob", original.message(), original.signature())).signatureValid());
        assertFalse(verify(new Package(original.messageId(), "bob", "bob", original.message(), original.signature())).signatureValid());
        assertFalse(verify(new Package(original.messageId(), "alice", "alice", original.message(), original.signature())).signatureValid());
        assertFalse(service.deliver(session, new Delivery(original, "alice", false)).accepted());
    }
    @Test void malformedAndBitFlippedSignaturesAreRejected() throws Exception {
        Package original = sign("alice");
        byte[] bytes = Base64.getDecoder().decode(original.signature()); bytes[0] ^= 1;
        assertFalse(verify(new Package(original.messageId(), "alice", "bob", original.message(), Base64.getEncoder().encodeToString(bytes))).signatureValid());
        Result malformed = verify(new Package(original.messageId(), "alice", "bob", original.message(), "!!!"));
        assertFalse(malformed.accepted()); assertEquals("MALFORMED_SIGNATURE", malformed.reason());
    }
    @Test void impersonationAndSubstitutionRevealTrustLimitation() throws Exception {
        Package forged = sign("mallory");
        assertFalse(verify(forged).signatureValid());
        service.trust(session, new Trust("bob", "alice", identities.get("mallory").publicKey()));
        Result substituted = verify(forged);
        assertTrue(substituted.signatureValid()); assertTrue(substituted.accepted()); assertFalse(substituted.keyMatchesPinned());
        service.trust(session, new Trust("bob", "alice", identities.get("alice").publicKey()));
        assertFalse(verify(forged).signatureValid());
    }
    @Test void missingTrustIsSeparateFromBadSignature() throws Exception {
        Package original = sign("alice");
        service.trust(session, new Trust("bob", "alice", ""));
        assertEquals("NO_TRUSTED_KEY", verify(original).reason());
        service.trust(session, new Trust("bob", "alice", identities.get("alice").publicKey()));
        assertTrue(verify(original).signatureValid());
    }
    @Test void replayProtectionAndLegitimateIdenticalText() throws Exception {
        Package first = sign("alice");
        assertTrue(deliver(first, false).accepted());
        assertTrue(deliver(first, false).accepted());
        Result rejected = deliver(first, true);
        assertTrue(rejected.signatureValid()); assertTrue(rejected.duplicate()); assertFalse(rejected.accepted());
        assertEquals("DUPLICATE_MESSAGE_ID", rejected.reason());
        Package second = sign("alice");
        assertNotEquals(first.messageId(), second.messageId());
        assertTrue(deliver(second, true).accepted());
        assertFalse(deliver(second, true).accepted());
        assertEquals(3, ((List<?>) service.state(session).get("inbox")).size());
    }
    @Test void storedTamperingAndPlaintextAreObservable() throws Exception {
        Package original = sign("alice"); deliver(original, true);
        Stored record = (Stored) ((List<?>) service.state(session).get("inbox")).get(0);
        assertEquals(original.message(), record.packet().message());
        Package edited = new Package(original.messageId(), "alice", "bob", "changed in store", original.signature());
        service.edit(session, record.deliveryId(), edited);
        Stored after = (Stored) ((List<?>) service.state(session).get("inbox")).get(0);
        assertEquals(original.signature(), after.packet().signature());
        assertFalse(verify(after.packet()).signatureValid());
        assertTrue(verify(original).payload().startsWith("signedchat-lab-v1:"));
    }
    @Test void invalidSigningKeysAndSessionIsolation() throws Exception {
        Package draft = service.prepare(session, new Prepare("alice", "bob", "hi"));
        assertThrows(IllegalArgumentException.class, () -> service.sign(session, new Sign(draft, "broken")));
        assertThrows(IllegalArgumentException.class, () -> service.trust(session, new Trust("bob", "alice", "broken")));
        String other = (String) service.create().get("sessionId");
        deliver(sign("alice"), false);
        assertTrue(((List<?>) service.state(other).get("inbox")).isEmpty());
        assertFalse(service.state(session).get("events").toString().contains(identities.get("alice").privateKey()));
        service.delete(session);
        assertThrows(IllegalArgumentException.class, () -> service.state(session));
    }
}
