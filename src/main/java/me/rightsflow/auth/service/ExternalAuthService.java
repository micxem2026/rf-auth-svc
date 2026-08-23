package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.LoginRequest;
import me.rightsflow.auth.dto.LoginResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class ExternalAuthService {

    private final AuthenticationManager externalLoginAuthenticationManager;
    private final JwtEncoder externalApiJwtEncoder;
    private final AuthorizationServerSettings authorizationServerSettings;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${rightsflow.oauth.token.external-login-ttl-seconds:1800}")
    private long loginTtlSeconds;

    /** Роли, которым разрешён вход через внешний API. */
    private static final Set<String> ALLOWED_LOGIN_ROLES = Set.of("ROLE_ADMIN", "ROLE_ADMIN_CLIENT");

    public LoginResponse login(LoginRequest request, WebAuthenticationDetails details) {
        UsernamePasswordAuthenticationToken authRequest =
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        authRequest.setDetails(details);

        Authentication authentication;
        try {
            authentication = externalLoginAuthenticationManager.authenticate(authRequest);
        } catch (AuthenticationException ex) {
            eventPublisher.publishEvent(new AuthenticationFailureBadCredentialsEvent(authRequest, ex));
            log.warn("External API login failed for username '{}': {}", request.getUsername(), ex.getMessage());
            throw ex;
        }

        RfAuthUserDetailsService.RfAuthUserPrincipal principal =
                (RfAuthUserDetailsService.RfAuthUserPrincipal) authentication.getPrincipal();

        if (!"USER".equals(principal.getUserType())) {
            throw new AccessDeniedException(
                    "Вход через внешний API доступен только пользователям с user_type='USER'.");
        }

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        boolean allowed = roles.stream().anyMatch(ALLOWED_LOGIN_ROLES::contains);
        if (!allowed) {
            throw new AccessDeniedException(
                    "Пользователю не назначена роль ADMIN_CLIENT (или ADMIN), доступ к внешнему API запрещён.");
        }

        eventPublisher.publishEvent(new AuthenticationSuccessEvent(authentication));

        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(loginTtlSeconds);

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(authorizationServerSettings.getIssuer())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .subject(principal.getUsername())
                .claim("user_id", principal.getUserId())
                .claim("username", principal.getUsername())
                .claim("display_name", principal.getDisplayName())
                .claim("email", principal.getEmail())
                .claim("user_type", principal.getUserType())
                .claim("roles", roles)
                .claim("token_use", "external_api_login")
                .build();

        // Ключи в JwkService — RSA (см. RSAKeyGenerator), поэтому RS256.
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).build();
        Jwt jwt = externalApiJwtEncoder.encode(JwtEncoderParameters.from(header, claims));

        LoginResponse response = new LoginResponse();
        response.setAccessToken(jwt.getTokenValue());
        response.setTokenType("Bearer");
        response.setExpiresIn(loginTtlSeconds);
        response.setUsername(principal.getUsername());
        response.setDisplayName(principal.getDisplayName());
        response.setRoles(new HashSet<>(roles));

        log.info("External API login succeeded: user='{}'", principal.getUsername());
        return response;
    }
}

