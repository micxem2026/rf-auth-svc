package me.rightsflow.auth.config;

import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Map;
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

            if (requestedTtlObj != null) {
                try {
                    long requestedTtl = Long.parseLong(requestedTtlObj.toString());
                    log.info("Client '{}' requested token TTL: {} seconds.", context.getRegisteredClient().getClientId(), requestedTtl);

                    // 1. Запрошенный TTL не должен быть отрицательным
                    if (requestedTtl <= 0) {
                        log.warn("Requested TTL ({}) is invalid. Using default TTL.", requestedTtl);
                        requestedTtl = defTokenTtl;
                    }

                    // 2. Ограничиваем запрошенный TTL максимальным значением с сервера
                    long finalTtl = Math.min(requestedTtl, maxTokenTtl);
                    if (finalTtl < requestedTtl) {
                        log.warn("Requested TTL ({}) exceeds server maximum ({}). Clamping to max.", requestedTtl, maxTokenTtl);
                    }

                    // 3. Получаем существующие клеймы, чтобы узнать время создания (iat)
                    var claims = context.getClaims();
                    Instant issuedAt = claims.build().getIssuedAt();
                    if (issuedAt == null) {
                        issuedAt = Instant.now();
                        claims.issuedAt(issuedAt); // Установим, если его не было
                    }

                    // 4. Вычисляем новое время истечения и обновляем клейм 'exp'
                    Instant newExpiry = issuedAt.plusSeconds(finalTtl);
                    claims.expiresAt(newExpiry);

                    var localDateTime = LocalDateTime.ofInstant(newExpiry, ZoneOffset.systemDefault());
                    log.info("Successfully set custom token TTL for client '{}' to {} seconds. New expiry: {}",
                            context.getRegisteredClient().getClientId(), finalTtl, localDateTime);

                } catch (NumberFormatException e) {
                    log.warn("Invalid format for 'requested_token_ttl' parameter: '{}'. Using default TTL.", requestedTtlObj);
                }
            }
        } else {
            log.warn("Authorization grant is not an instance of OAuth2AuthorizationGrantAuthenticationToken.");
        }

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {

            // Для Client Credentials Grant
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                context.getClaims().claim("client_id", context.getRegisteredClient().getClientId());
                context.getClaims().claim("scope", context.getAuthorizedScopes());

                log.debug("Customized JWT for client credentials grant: client_id={}, scopes={}",
                        context.getRegisteredClient().getClientId(), context.getAuthorizedScopes());
            }

            // Для других типов grant (если будут добавлены в будущем)
            if (context.getPrincipal() != null &&
                    context.getPrincipal().getPrincipal() instanceof RfAuthUserDetailsService.RfAuthUserPrincipal userPrincipal) {

                context.getClaims().claim("user_id", userPrincipal.getUserId());
                context.getClaims().claim("username", userPrincipal.getUsername());
                context.getClaims().claim("display_name", userPrincipal.getDisplayName());
                context.getClaims().claim("email", userPrincipal.getEmail());
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
