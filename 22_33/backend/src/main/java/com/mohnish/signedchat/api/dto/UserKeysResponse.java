package com.mohnish.signedchat.api.dto;

import com.mohnish.signedchat.model.ChatUser;
import java.util.Base64;

/** Explicit demo-only lookup of the server-held key pair. */
public record UserKeysResponse(String name, String publicKey, String privateKey, boolean trusted) {
    public static UserKeysResponse of(ChatUser user, boolean trusted) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new UserKeysResponse(user.getName(),
            encoder.encodeToString(user.getPublicKey().getEncoded()),
            encoder.encodeToString(user.getPrivateKey().getEncoded()), trusted);
    }

    @Override public String toString() {
        return "UserKeysResponse[name=" + name + ", privateKey=[REDACTED]]";
    }
}
