package com.mohnish.signedchat.config;

import com.mohnish.signedchat.encoding.PayloadEncoder;
import com.mohnish.signedchat.service.MessagingService;
import com.mohnish.signedchat.service.SignatureService;
import com.mohnish.signedchat.store.TrustedKeyStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Exposes the core (framework-free) classes as Spring beans so they can be
 * injected into the API layer without being modified.
 */
@Configuration
public class MessagingConfig {

    @Bean
    public SignatureService signatureService() {
        return new SignatureService();
    }

    @Bean
    public PayloadEncoder payloadEncoder() {
        return new PayloadEncoder();
    }

    @Bean
    public TrustedKeyStore trustedKeyStore() {
        return new TrustedKeyStore();
    }

    @Bean
    public MessagingService messagingService(
        SignatureService signatureService,
        PayloadEncoder payloadEncoder,
        TrustedKeyStore trustedKeyStore
    ) {
        return new MessagingService(
            signatureService,
            payloadEncoder,
            trustedKeyStore
        );
    }
}
