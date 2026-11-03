package com.mohnish.signedchat.api.dto;

import com.mohnish.signedchat.model.ChatUser;

/** {@code publicKey} is the Base64-encoded X.509 (SubjectPublicKeyInfo) key. */
public record UserResponse(String name, String publicKey, boolean trusted) {
    public static UserResponse of(ChatUser user, boolean trusted) {
        return new UserResponse(
            user.getName(),
            java.util.Base64.getEncoder().encodeToString(
                user.getPublicKey().getEncoded()
            ),
            trusted
        );
    }
}
