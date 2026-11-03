package com.mohnish.signedchat.api.dto;

import com.mohnish.signedchat.model.ChatUser;
import java.util.Base64;

/** Creation returns the PKCS#8 private key; explicit demo key lookup also exposes it. */
public record CreatedUserResponse(String name, String publicKey, String privateKey, boolean trusted) {
    public static CreatedUserResponse of(ChatUser user, boolean trusted) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new CreatedUserResponse(user.getName(), encoder.encodeToString(user.getPublicKey().getEncoded()),
            encoder.encodeToString(user.getPrivateKey().getEncoded()), trusted);
    }
    @Override public String toString() { return "CreatedUserResponse[name=" + name + ", privateKey=[REDACTED]]"; }
}
