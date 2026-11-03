package com.mohnish.signedchat.service;

import com.mohnish.signedchat.api.UserAlreadyExistsException;
import com.mohnish.signedchat.api.UserNotFoundException;
import com.mohnish.signedchat.model.ChatUser;
import com.mohnish.signedchat.store.TrustedKeyStore;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * Server-side registry of chat users. The server generates and holds each
 * user's Ed25519 key pair. The private key is returned at creation and through
 * the explicit demo key lookup. Ordinary user list/lookups remain public-only.
 */
@Service
public class UserService {

    private final SignatureService signatureService;
    private final TrustedKeyStore trustedKeyStore;
    private final Map<String, ChatUser> users = new ConcurrentHashMap<>();

    public UserService(
        SignatureService signatureService,
        TrustedKeyStore trustedKeyStore
    ) {
        this.signatureService = signatureService;
        this.trustedKeyStore = trustedKeyStore;
    }

    /**
     * Creates a user with a fresh key pair. When {@code trusted} is false the
     * public key is not added to the trusted key store, so messages signed by
     * this user are rejected on receipt (useful for simulating an attacker).
     */
    public ChatUser create(String name, boolean trusted)
        throws GeneralSecurityException {
        ChatUser user = new ChatUser(name, signatureService.generateKeyPair());
        if (users.putIfAbsent(name, user) != null) {
            throw new UserAlreadyExistsException(name);
        }
        if (trusted) {
            trustedKeyStore.registerTrustedKey(name, user.getPublicKey());
        }
        return user;
    }

    public ChatUser get(String name) {
        ChatUser user = users.get(name);
        if (user == null) {
            throw new UserNotFoundException(name);
        }
        return user;
    }

    public List<ChatUser> list() {
        return new ArrayList<>(users.values());
    }

    public boolean isTrusted(String name) {
        return trustedKeyStore.isTrusted(name);
    }
}
