package com.mohnish.signedchat.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Cross-origin access is limited to the explicitly configured frontend origin. */
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    private final String frontendOrigin;

    public CorsConfig(@Value("${app.cors.allowed-origin:}") String frontendOrigin) {
        this.frontendOrigin = frontendOrigin;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        if (!frontendOrigin.isBlank()) {
            registry.addMapping("/api/**")
                .allowedOrigins(frontendOrigin)
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("Content-Type", "Accept")
                .allowCredentials(false)
                .maxAge(3600);
        }
    }
}
