package com.dev.auth_service.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtConfig {

    @Bean
    public RSAPrivateKey privateKey(RsaKeyLoader keyLoader) {
        return keyLoader.loadPrivateKey("classpath:keys/private.pem");
    }

    @Bean
    public RSAPublicKey publicKey(RsaKeyLoader keyLoader) {
        return keyLoader.loadPublicKey("classpath:keys/public.pem");
    }
}
