package com.mohnish.signedchat.encoding;

public class PayloadEncoder {

    public String generateNonce() {
        byte[] nonceBytes = new byte[32];
        new java.security.SecureRandom().nextBytes(nonceBytes);
        return java.util.Base64.getEncoder().encodeToString(nonceBytes);
    }

    public byte[] encode(String senderId, String recipientId, String content, String nonce) {
        java.util.Base64.Encoder encoder = java.util.Base64.getEncoder();
        String payload = "signedchat-v2:";
        for (String field : new String[] {nonce, senderId, recipientId, content}) {
            payload += encoder.encodeToString(field.getBytes(java.nio.charset.StandardCharsets.UTF_8)) + ":";
        }
        return payload.substring(0, payload.length() - 1).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    public static String encodePayload(
        String message,
        byte[] signature,
        String senderId,
        String receiverId,
        String nonce
    ) {
        String encodedMessage = java.util.Base64.getEncoder().encodeToString(
            message.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        String encodedSignature = java.util.Base64.getEncoder().encodeToString(
            signature
        );

        String encodedSenderId = java.util.Base64.getEncoder().encodeToString(
            senderId.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        String encodedReceiverId = java.util.Base64.getEncoder().encodeToString(
            receiverId.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        return (
            encodedMessage +
            ":" +
            encodedSignature +
            ":" +
            encodedSenderId +
            ":" +
            encodedReceiverId + ":" + java.util.Base64.getEncoder().encodeToString(nonce.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        );
    }

    public static String[] decodePayload(String payload) {
        String[] parts = payload.split(":", -1);
        if (parts.length != 5) {
            throw new IllegalArgumentException("Invalid payload format");
        }
        return parts;
    }
}
