package com.mohnish.signedchat.model;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ChatUser {

    private final String name; // once a user is created with the name, there won't be any changes
    private final KeyPair keyPair;

    public ChatUser(final String name, final KeyPair keyPair) {
        this.name = name;
        this.keyPair = keyPair;
    }

    public String getName() {
        return name;
    }

    public PublicKey getPublicKey() {
        return this.keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }
}
