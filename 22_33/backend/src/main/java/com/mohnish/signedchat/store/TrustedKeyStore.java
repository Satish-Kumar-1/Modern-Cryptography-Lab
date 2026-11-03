package com.mohnish.signedchat.store;

import java.security.PublicKey;
import java.util.Map;

public class TrustedKeyStore {

    private final Map<String, PublicKey> trustedKeySet = new java.util.HashMap<>();

    public synchronized void registerTrustedKey(String userId, PublicKey publicKey) {
        this.trustedKeySet.put(userId, publicKey);
    }

    public synchronized PublicKey getTrustedKey(String userId) {
        return this.trustedKeySet.get(userId);
    }

    public synchronized boolean isTrusted(String userId) {
        return this.trustedKeySet.containsKey(userId);
    }
}
