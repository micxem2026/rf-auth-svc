package me.rightsflow.auth.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.entity.JwkEntity;
import me.rightsflow.auth.repository.JwkRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwkService {

    private final JwkRepository jwkRepository;
    private RSAKey currentKey;

    @Transactional
    public void initializeKeys() {
        log.info("Initializing JWK keys");

        Optional<JwkEntity> latestKey = jwkRepository.findLatestActiveKey(LocalDateTime.now());

        if (latestKey.isEmpty()) {
            log.info("No active keys found, generating new key");
            generateAndSaveNewKey();
        } else {
            log.info("Active key found, loading it");
            loadCurrentKey(latestKey.get());
        }
    }

    public void generateAndSaveNewKey() {
        try {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();

            JwkEntity jwkEntity = new JwkEntity();
            jwkEntity.setKid(UUID.fromString(rsaKey.getKeyID()));
            jwkEntity.setJwkSet(rsaKey.toJSONString());
            jwkEntity.setCreatedAt(LocalDateTime.now());
            jwkEntity.setExpirationDate(LocalDateTime.now().plusYears(1));

            jwkRepository.save(jwkEntity);
            this.currentKey = rsaKey;

            log.info("New JWK key generated and saved with kid: {}", rsaKey.getKeyID());

        } catch (JOSEException e) {
            log.error("Error generating JWK key", e);
            throw new RuntimeException("Failed to generate JWK key", e);
        }
    }

    private void loadCurrentKey(JwkEntity jwkEntity) {
        try {
            this.currentKey = RSAKey.parse(jwkEntity.getJwkSet());
            log.info("Current key loaded with kid: {}", currentKey.getKeyID());
        } catch (Exception e) {
            log.error("Error loading current key", e);
            throw new RuntimeException("Failed to load current key", e);
        }
    }

    public RSAKey getCurrentKey() {
        if (currentKey == null) {
            initializeKeys();
        }
        return currentKey;
    }

    @Transactional
    public RSAPublicKey getCurrentPublicKey() {
        try {
            return getCurrentKey().toRSAPublicKey();
        } catch (JOSEException e) {
            log.error("Error getting current public key", e);
            throw new RuntimeException("Failed to get current public key", e);
        }
    }

    @Transactional
    public RSAPrivateKey getCurrentPrivateKey() {
        try {
            return getCurrentKey().toRSAPrivateKey();
        } catch (JOSEException e) {
            log.error("Error getting current private key", e);
            throw new RuntimeException("Failed to get current private key", e);
        }
    }

    @Transactional
    public String getCurrentKeyId() {
        return getCurrentKey().getKeyID();
    }

    @Transactional(readOnly = true)
    public JWKSet getJWKSet() {
        List<JwkEntity> activeKeys = jwkRepository.findActiveKeys(LocalDateTime.now());

        List<JWK> jwks = activeKeys.stream()
                .map(entity -> {
                    try {
                        return JWK.parse(entity.getJwkSet());
                    } catch (Exception e) {
                        log.error("Error parsing JWK from database", e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();

        return new JWKSet(jwks);
    }

    @Scheduled(cron = "0 0 0 * * ?") // Каждый день в полночь
    @Transactional
    public void rotateKeysIfNeeded() {
        log.info("Checking if key rotation is needed");

        Optional<JwkEntity> latestKey = jwkRepository.findLatestActiveKey(LocalDateTime.now());

        if (latestKey.isPresent()) {
            LocalDateTime keyExpiration = latestKey.get().getExpirationDate();
            LocalDateTime rotationTime = keyExpiration.minusDays(1);

            if (LocalDateTime.now().isAfter(rotationTime)) {
                log.info("Key rotation needed, generating new key");
                generateAndSaveNewKey();
            }
        }

        // Удаляем просроченные ключи (старше 24 часов после истечения)
        LocalDateTime cleanupTime = LocalDateTime.now().minusDays(1);
        jwkRepository.deleteByExpirationDateBefore(cleanupTime);
    }
}
