package com.mohnish.signedchat;

import com.mohnish.signedchat.service.SignatureService;
import com.mohnish.signedchat.encoding.PayloadEncoder;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CoreSignatureTests {
    @Test void convenienceSigningUsesSameAuthenticatedEnvelopeAndCopiesSignature() throws Exception {
        SignatureService service = new SignatureService();
        var pair = service.generateKeyPair();
        var message = service.signMessage("exact café", pair.getPrivate(), "alice", "bob");
        assertTrue(service.verify(new PayloadEncoder().encode("alice", "bob", "exact café", message.getNonce()), message.getSignature(), pair.getPublic()));
        assertFalse(service.verify(new PayloadEncoder().encode("alice", "mallory", "exact café", message.getNonce()), message.getSignature(), pair.getPublic()));
        byte[] copy = message.getSignature(); copy[0] ^= 1;
        assertTrue(service.verify(new PayloadEncoder().encode("alice", "bob", "exact café", message.getNonce()), message.getSignature(), pair.getPublic()));
    }
}
