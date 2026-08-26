package com.dev.order_service.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {
    @Bean
    public RSAPublicKey publicKey(RSAPublicKeyLoader keyLoader) {
        return keyLoader.loadPublicKey("classpath:keys/public.pem");
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAPublicKey publicKey) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(publicKey)
                .build();

        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("auth-service"));

        return decoder;
    }
}
