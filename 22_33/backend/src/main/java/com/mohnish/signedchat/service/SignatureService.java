package com.mohnish.signedchat.service;

import com.mohnish.signedchat.model.SignedMessage;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureService {

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        return generator.generateKeyPair();
    }

    public SignedMessage signMessage(
        String message,
        PrivateKey privateKey,
        String senderId,
        String receiverId
    ) throws GeneralSecurityException {
        com.mohnish.signedchat.encoding.PayloadEncoder encoder = new com.mohnish.signedchat.encoding.PayloadEncoder();
        String nonce = encoder.generateNonce();
        byte[] payload = encoder.encode(senderId, receiverId, message, nonce);
        return new SignedMessage(message, sign(payload, privateKey), senderId, receiverId, nonce);
    }

    public byte[] sign(byte[] payload, PrivateKey privateKey)
        throws GeneralSecurityException {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(privateKey);
        signer.update(payload);
        return signer.sign();
    }

    //verifier service
    public boolean verify(byte[] message, byte[] signature, PublicKey publicKey)
        throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(message);

        return verifier.verify(signature);
    }
}
