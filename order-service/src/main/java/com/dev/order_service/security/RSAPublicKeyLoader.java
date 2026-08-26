package com.dev.order_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class RSAPublicKeyLoader {
    private final ResourceLoader resourceLoader;

    public RSAPublicKey loadPublicKey(String location) {
        try {
            Resource resource = resourceLoader.getResource(location);

            String key = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            String publicKeyContent = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] decodedKey = Base64.getDecoder().decode(publicKeyContent);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {

            throw new IllegalStateException(
                    "Não foi possível carregar a chave pública RSA",
                    e
            );
        }
    }
}
