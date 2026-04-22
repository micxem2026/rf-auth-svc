package me.rightsflow.auth.config;

import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.entity.OAuth2RegisteredClientEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.OAuth2RegisteredClientRepository;
import me.rightsflow.auth.repository.UserRepository;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class RfAuthJwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    // Внедряем максимальное и дефолтное время жизни токена из конфигурации
    // По умолчанию - 1 день (86400 секунд)
    @Value("${rightsflow.oauth.token.max-ttl-seconds:86400}")
    private long maxTokenTtl;
    // По умолчанию - 1 час (3600 секунд)
    @Value("${rightsflow.oauth.token.default-ttl-seconds:3600}")
    private long defTokenTtl;

    private final OAuth2RegisteredClientRepository clientsRepo;
    private final UserRepository userRepository;

    public RfAuthJwtTokenCustomizer(OAuth2RegisteredClientRepository clientsRepo,
                                    UserRepository userRepository) {
        this.clientsRepo = clientsRepo;
        this.userRepository = userRepository;
    }

    @Override
    public void customize(JwtEncodingContext context) {

        // Получаем объект аутентификации, который представляет сам ЗАПРОС НА ТОКЕН (grant),
        // а не аутентификацию клиента.
        Authentication authorizationGrant = context.getAuthorizationGrant();

        // Проверяем, является ли это запросом на получение токена (любой grant_type)
        if (authorizationGrant instanceof OAuth2AuthorizationGrantAuthenticationToken tokenRequest) {
            // Получаем дополнительные (нестандартные) параметры из запроса
            Map<String, Object> additionalParameters = tokenRequest.getAdditionalParameters();

            // Наш кастомный параметр должен быть здесь
            Object requestedTtlObj = additionalParameters.get("requested_token_ttl");

            OAuth2RegisteredClientEntity entity = null;
            if (tokenRequest.getPrincipal() instanceof OAuth2ClientAuthenticationToken principal) {
                entity = clientsRepo.findByClientId(principal.getName()).orElse(null);
            }

            Instant clientSecretExpirationDate = null;
            if (entity != null) {
                clientSecretExpirationDate = entity.getClientSecretExpiresAt() != null ? entity.getClientSecretExpiresAt().atZone(ZoneId.systemDefault()).toInstant() : null;
            }

            log.debug("Found clientSecretExpirationDate: {}", clientSecretExpirationDate != null ? LocalDateTime.ofInstant(clientSecretExpirationDate, ZoneId.systemDefault()) : null);

            // 1. Получаем существующие клеймы, чтобы узнать время создания (iat)
            var claims = context.getClaims();
            Instant issuedAt = claims.build().getIssuedAt();
            if (issuedAt == null) {
                issuedAt = Instant.now();
                claims.issuedAt(issuedAt); // Установим, если его не было
            }

            if (requestedTtlObj != null) {
                try {
                    long requestedTtl = Long.parseLong(requestedTtlObj.toString());
                    log.info("Client '{}' requested token TTL: {} seconds.", context.getRegisteredClient().getClientId(), requestedTtl);

                    // 2. Запрошенный TTL не должен быть отрицательным
                    if (requestedTtl <= 0) {
                        log.warn("Requested TTL ({}) is invalid. Using default TTL.", requestedTtl);
                        requestedTtl = defTokenTtl;
                    }

                    // 3. Ограничиваем запрошенный TTL максимальным значением с сервера
                    long finalTtl = Math.min(requestedTtl, maxTokenTtl);
                    if (finalTtl < requestedTtl) {
                        log.warn("Requested TTL ({}) exceeds server maximum ({}). Clamping to max.", requestedTtl, maxTokenTtl);
                    }

                    // 4. Вычисляем новое время истечения и обновляем клейм 'exp'
                    Instant newExpiry = issuedAt.plusSeconds(finalTtl);
                    if (clientSecretExpirationDate != null && newExpiry.isAfter(clientSecretExpirationDate)) {
                        newExpiry = clientSecretExpirationDate;
                        finalTtl = (newExpiry.toEpochMilli() - issuedAt.toEpochMilli()) / 1000;
                        log.warn("Clamping ttl to client secret expiration date ({}).", finalTtl);
                    }
                    claims.expiresAt(newExpiry);

                    var localDateTime = LocalDateTime.ofInstant(newExpiry, ZoneOffset.systemDefault());
                    log.info("Successfully set custom token TTL for client '{}' to {} seconds. New expiry: {}",
                            context.getRegisteredClient().getClientId(), finalTtl, localDateTime);

                } catch (NumberFormatException e) {
                    log.warn("Invalid format for 'requested_token_ttl' parameter: '{}'. Using default TTL.", requestedTtlObj);
                }
            } else {
                Instant newExpiry = issuedAt.plusSeconds(defTokenTtl);
                if (clientSecretExpirationDate != null && newExpiry.isAfter(clientSecretExpirationDate)) {
                    newExpiry = clientSecretExpirationDate;
                    long finalTtl = (newExpiry.toEpochMilli() - issuedAt.toEpochMilli()) / 1000;
                    log.warn("Clamping ttl to client secret expiration date ({}).", finalTtl);
                }
                claims.expiresAt(newExpiry);
            }
        } else {
            log.warn("Authorization grant is not an instance of OAuth2AuthorizationGrantAuthenticationToken.");
        }

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

            // Для Client Credentials Grant
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                String clientId = context.getRegisteredClient().getClientId();
                context.getClaims().claim("client_id", clientId);
                context.getClaims().claim("scope", context.getAuthorizedScopes());

                UserEntity serviceUser = userRepository.findByUsernameWithRoles(clientId)
                        .orElseThrow(() -> new IllegalArgumentException("User not found with username: " + clientId));
                List<String> roles = Optional.of(serviceUser)
                        .filter(u -> "SERVICE".equals(u.getUserType()))
                        .map(u -> u.getRoles().stream()
                                .map(role -> "ROLE_" + role.getName())
                                .collect(Collectors.toList()))
                        .orElse(Collections.emptyList());
                context.getClaims().claim("roles", roles);
                context.getClaims().claim("user_id", serviceUser.getId());
                context.getClaims().claim("username", serviceUser.getUsername());
                context.getClaims().claim("display_name", serviceUser.getDisplayName());
                context.getClaims().claim("email", serviceUser.getEmail());
                context.getClaims().claim("user_type", serviceUser.getUserType());

                log.debug("Customized JWT for client credentials grant: client_id={}, scopes={}, roles={}",
                        context.getRegisteredClient().getClientId(), context.getAuthorizedScopes(), new ArrayList<>(roles)
                );
            }

            // Для других типов grant (если будут добавлены в будущем)
            if (context.getPrincipal() != null &&
                    context.getPrincipal().getPrincipal() instanceof RfAuthUserDetailsService.RfAuthUserPrincipal userPrincipal) {

                context.getClaims().claim("user_id", userPrincipal.getUserId());
                context.getClaims().claim("username", userPrincipal.getUsername());
                context.getClaims().claim("display_name", userPrincipal.getDisplayName());
                context.getClaims().claim("email", userPrincipal.getEmail());
                context.getClaims().claim("user_type", userPrincipal.getUserType());
                context.getClaims().claim("roles", userPrincipal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()));

                log.debug("Customized JWT for user: username={}, roles={}",
                        userPrincipal.getUsername(),
                        userPrincipal.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()));
            }
        }
    }
}
