package me.rightsflow.auth.config;

import com.nimbusds.jose.jwk.JWK;
import me.rightsflow.auth.service.JwkService;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

@RequiredArgsConstructor
@Slf4j
public class RfAuthJWKSource implements JWKSource<SecurityContext> {

    private final JwkService jwkService;

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        try {
            JWKSet jwkSet = jwkService.getJWKSet();
            return jwkSelector.select(jwkSet);
        } catch (Exception e) {
            log.error("Error getting JWK set", e);
            throw new RuntimeException("Failed to get JWK set", e);
        }
    }
}
