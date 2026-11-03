package com.mohnish.signedchat.api.dto;

import com.mohnish.signedchat.model.SignedMessage;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.Base64;

/** Wire form of a {@link SignedMessage}; {@code signature} is Base64. */
public record SignedMessageDto(
    @NotNull String message,
    @NotBlank String signature,
    @NotBlank String senderId,
    @NotBlank String receiverId,
    @NotBlank @jakarta.validation.constraints.Pattern(regexp = "[A-Za-z0-9+/]{43}=") String nonce
) {
    public static SignedMessageDto of(SignedMessage m) {
        return new SignedMessageDto(
            m.getMessage(),
            Base64.getEncoder().encodeToString(m.getSignature()),
            m.getSenderId(),
            m.getReceiverId(),
            m.getNonce()
        );
    }

    /** @throws IllegalArgumentException if the signature is not valid Base64 */
    public SignedMessage toDomain() {
        return new SignedMessage(
            message,
            Base64.getDecoder().decode(signature),
            senderId,
            receiverId,
            nonce
        );
    }
}
