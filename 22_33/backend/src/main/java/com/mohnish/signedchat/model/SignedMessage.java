package com.mohnish.signedchat.model;

public class SignedMessage {

    private final String nonce;
    private final String message;
    private final byte[] signature;
    private final String senderId;
    private final String receiverId;

    public SignedMessage(
        String message,
        byte[] signature,
        String senderId,
        String receiverId,
        String nonce
    ) {
        this.nonce = nonce;
        this.message = message;
        this.signature = signature == null ? null : signature.clone();
        this.senderId = senderId;
        this.receiverId = receiverId;
    }

    public String getNonce() { return nonce; }

    public String getMessage() {
        return message;
    }

    public byte[] getSignature() {
        return signature == null ? null : signature.clone();
    }

    public String getSenderId() {
        return senderId;
    }

    public String getReceiverId() {
        return receiverId;
    }

    public String toString() {
        return (
            "SignedMessage{" +
            "message='" +
            message +
            '\'' +
            ", signature=" +
            java.util.Base64.getEncoder().encodeToString(signature) +
            ", senderId='" +
            senderId +
            '\'' +
            ", receiverId='" +
            receiverId +
            '\'' +
            '}'
        );
    }
}
