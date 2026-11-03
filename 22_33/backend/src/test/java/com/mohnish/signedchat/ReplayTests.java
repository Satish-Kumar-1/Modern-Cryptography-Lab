package com.mohnish.signedchat;

import com.mohnish.signedchat.service.*;
import com.mohnish.signedchat.model.*;
import com.mohnish.signedchat.encoding.PayloadEncoder;
import com.mohnish.signedchat.store.TrustedKeyStore;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ReplayTests {
    @Test void nonceIsSignedAndConsumedOnlyAfterValidDelivery() throws Exception {
        SignatureService signatures = new SignatureService();
        var pair = signatures.generateKeyPair();
        TrustedKeyStore trust = new TrustedKeyStore();
        trust.registerTrustedKey("alice", pair.getPublic());
        MessagingService messaging = new MessagingService(signatures, new PayloadEncoder(), trust);
        var first = signatures.signMessage("same text", pair.getPrivate(), "alice", "bob");
        var changed = new SignedMessage(first.getMessage(), first.getSignature(), "alice", "bob", new PayloadEncoder().generateNonce());
        assertFalse(messaging.receive(changed, "bob"));
        assertTrue(messaging.receive(first, "bob"));
        assertFalse(messaging.receive(first, "bob"));
        var second = signatures.signMessage("same text", pair.getPrivate(), "alice", "bob");
        assertNotEquals(first.getNonce(), second.getNonce());
        assertTrue(messaging.receive(second, "bob"));
        assertEquals(2, messaging.getInbox("bob").size());
    }
}
