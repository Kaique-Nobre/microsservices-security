package com.dev.auth_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class RsaKeyLoader {

    private final ResourceLoader resourceLoader;

    public RSAPrivateKey loadPrivateKey(String location) {
        try {
            Resource resource = resourceLoader.getResource(location);

            String key = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

            String privateKeyContent = key
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] decodeKey = Base64.getDecoder().decode(privateKeyContent);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        } catch (IOException | NoSuchAlgorithmException |
                 java.security.spec.InvalidKeySpecException e) {

            throw new IllegalStateException(
                    "Não foi possível carregar a chave privada RSA",
                    e
            );
        }
    }

    public RSAPublicKey loadPublicKey(String location) {
        try {
            Resource resource = resourceLoader.getResource(location);

            String key = new String(
                    resource.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8
            );

            String publicKeyContent = key
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] decodedKey = Base64.getDecoder()
                    .decode(publicKeyContent);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (IOException | NoSuchAlgorithmException |
                 java.security.spec.InvalidKeySpecException e) {

            throw new IllegalStateException(
                    "Não foi possível carregar a chave pública RSA",
                    e
            );
        }
    }
}
