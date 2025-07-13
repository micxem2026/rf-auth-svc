package me.rightsflow.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.ClientRegistrationRequest;
import me.rightsflow.auth.dto.ClientRegistrationResponse;
import me.rightsflow.auth.entity.OAuth2RegisteredClientEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.OAuth2RegisteredClientRepository;
import me.rightsflow.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Slf4j
public class ClientRegistrationService {

    @Value("${rightsflow.oauth.token.max-ttl-seconds:86400}")
    private long maxTokenTtl;
    @Value("${rightsflow.oauth.token.default-ttl-seconds:3600}")
    private long defTokenTtl;
    @Value("${rightsflow.oauth.token.refresh-ttl-days:90}")
    private long refreshTtlDays;

    private final JpaRegisteredClientRepository registeredClientRepository;
    private final OAuth2RegisteredClientRepository clientRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    private static final Set<String> ALLOWED_GRANT_TYPES = Set.of(
            "client_credentials",
            "authorization_code",
            "refresh_token"
    );

    private static final Set<String> ALL_AVAILABLE_SCOPES = Set.of(
            "read", "write", "create", "update", "delete", "execute",
            "openid", "profile", "email"
    );

    @Autowired
    public ClientRegistrationService(JpaRegisteredClientRepository registeredClientRepository,
                                     OAuth2RegisteredClientRepository clientRepository,
                                     UserRepository userRepository,
                                     PasswordEncoder passwordEncoder,
                                     @Qualifier("securityObjectMapper") ObjectMapper objectMapper) {
        this.registeredClientRepository = registeredClientRepository;
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
        this.objectMapper = objectMapper;
        this.userRepository = userRepository;
    }

    @Transactional
    public ClientRegistrationResponse registerClient(ClientRegistrationRequest request, Authentication authentication) {

        // Проверяем права пользователя
        validateUserPermissions(authentication, request.getScopes());

        // Проверяем уникальность client_id
        if (registeredClientRepository.existsByClientId(request.getClientId())) {
            throw new IllegalArgumentException("Client ID already exists: " + request.getClientId());
        }

        // Проверяем grant types
        validateGrantTypes(request.getGrantTypes());

        // Генерируем client secret
        String clientSecret = generateClientSecret();
        String encodedClientSecret = passwordEncoder.encode(clientSecret);

        Instant clientSecretExpiresAt = Optional.ofNullable(request.getClientSecretExpiresAt())
                .map(d -> d.atZone(ZoneId.systemDefault()).toInstant()).orElse(null);

        // Создаем RegisteredClient
        RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.getClientId())
                .clientSecret(encodedClientSecret)
                .clientSecretExpiresAt(clientSecretExpiresAt)
                .clientName(request.getClientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // Добавляем grant types
        request.getGrantTypes().forEach(grantType ->
                clientBuilder.authorizationGrantType(new AuthorizationGrantType(grantType)));

        // Добавляем scopes
        request.getScopes().forEach(clientBuilder::scope);

        // Добавляем redirect URIs для authorization_code grant
        if (request.getGrantTypes().contains("authorization_code") && request.getRedirectUris() != null) {
            request.getRedirectUris().forEach(clientBuilder::redirectUri);
        }

        // Настройки клиента
        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(request.getRequireAuthorizationConsent())
                .requireProofKey(request.getRequireProofKey())
                .build();
        clientBuilder.clientSettings(clientSettings);

        // Настройки токенов
        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                .reuseRefreshTokens(request.getReuseRefreshTokens());

        long tokenTtlSeconds = request.getAccessTokenTtlSeconds() != null ? request.getAccessTokenTtlSeconds() : defTokenTtl;
        tokenTtlSeconds = Math.min(maxTokenTtl, tokenTtlSeconds);
        tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(tokenTtlSeconds));
        log.info("Set tokenTtl to {} seconds for client '{}'", tokenTtlSeconds, request.getClientId());

        Duration refreshTtlDaysDuration = Duration.ofDays(refreshTtlDays);

        long refreshTokenTtlSeconds = request.getRefreshTokenTtlSeconds() != null ? request.getRefreshTokenTtlSeconds() : refreshTtlDaysDuration.toSeconds();
        tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtlSeconds));
        log.info("Set refreshTokenTtl to {} seconds for client '{}'", refreshTokenTtlSeconds, request.getClientId());

        clientBuilder.tokenSettings(tokenSettingsBuilder.build());
        RegisteredClient registeredClient = clientBuilder.build();

        // Сохраняем в базу с указанием создателя
        OAuth2RegisteredClientEntity entity = toEntityWithCreator(registeredClient, authentication.getName());
        clientRepository.save(entity);

        log.info("Registered new client: {} by user: {}", request.getClientId(), authentication.getName());

        // Создаем пользователя
        makeServiceUser(request.getClientId(), request.getClientName(), clientSecret);

        // Возвращаем ответ с незашифрованным client secret
        return createResponse(registeredClient, clientSecret, authentication.getName());
    }

    @Transactional(readOnly = true)
    public List<ClientRegistrationResponse> getUserClients() {
        // Используем прямой JPA репозиторий, чтобы получить сущности с полем createdBy
        return clientRepository.findUserCreatedClients()
                .stream()
                // Конвертируем сущность напрямую в DTO ответа
                .map(this::entityToResponse)
                .toList();
    }

    private ClientRegistrationResponse entityToResponse(OAuth2RegisteredClientEntity entity) {
        ClientRegistrationResponse response = new ClientRegistrationResponse();
        response.setId(entity.getId());
        response.setClientId(entity.getClientId());
        response.setClientName(entity.getClientName());
        response.setClientIdIssuedAt(entity.getClientIdIssuedAt());
        response.setClientSecretExpiresAt(entity.getClientSecretExpiresAt());
        response.setCreatedAt(entity.getCreatedAt());
        response.setCreatedBy(entity.getCreatedBy());

        // Конвертируем строки через запятую обратно в Set
        response.setGrantTypes(StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes()));
        response.setScopes(StringUtils.commaDelimitedListToSet(entity.getScopes()));
        response.setRedirectUris(StringUtils.commaDelimitedListToSet(entity.getRedirectUris()));

        // Секрет клиента не передаем в ответе
        response.setClientSecret(null);

        try {
            ClientSettings clientSettings = objectMapper.readValue(entity.getClientSettings(), ClientSettings.class);
            TokenSettings tokenSettings = objectMapper.readValue(entity.getTokenSettings(), TokenSettings.class);
            response.setRequireAuthorizationConsent(clientSettings.isRequireAuthorizationConsent());
            response.setRequireProofKey(clientSettings.isRequireProofKey());
            response.setReuseRefreshTokens(tokenSettings.isReuseRefreshTokens());
        } catch (Exception e) {
            throw new RuntimeException("Error deserializing client settings", e);
        }

        return response;
    }

    @Transactional
    public void deleteClient(String clientId, Authentication authentication) {
        OAuth2RegisteredClientEntity entity = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not found: " + clientId));

        if ("system".equals(entity.getCreatedBy())) {
            throw new IllegalArgumentException("Cannot delete system client");
        }

        if (!authentication.getName().equals(entity.getCreatedBy())) {
            throw new IllegalArgumentException("Access denied: can only delete own clients");
        }

        registeredClientRepository.deleteByClientId(clientId);
        deleteByUsername(clientId);
        log.info("Deleted client: {} by user: {}", clientId, authentication.getName());
    }

    private void deleteByUsername(String clientId) {
        userRepository.findByUsername(clientId)
                .ifPresent(entity -> {
                    if (!"USER".equals(entity.getUserType())) {
                        userRepository.delete(entity);
                        log.info("Deleted service user: {}", clientId);
                    } else {
                        log.warn("Attempt to delete not service user: {}", clientId);
                        throw new IllegalArgumentException("Cannot delete not service user");
                    }
                });
    }

    private void validateUserPermissions(Authentication authentication, Set<String> requestedScopes) {
        // Проверяем, что пользователь имеет роль ADMIN
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> "ROLE_ADMIN".equals(auth.getAuthority()));

        if (!isAdmin) {
            throw new IllegalArgumentException("Access denied: ADMIN role required for client registration");
        }

        // Проверяем, что запрашиваемые scopes входят в доступные
        Set<String> invalidScopes = requestedScopes.stream()
                .filter(scope -> !ALL_AVAILABLE_SCOPES.contains(scope))
                .collect(Collectors.toSet());

        if (!invalidScopes.isEmpty()) {
            throw new IllegalArgumentException("Invalid scopes: " + String.join(", ", invalidScopes));
        }
    }

    private void validateGrantTypes(Set<String> grantTypes) {
        Set<String> invalidGrantTypes = grantTypes.stream()
                .filter(grantType -> !ALLOWED_GRANT_TYPES.contains(grantType))
                .collect(Collectors.toSet());

        if (!invalidGrantTypes.isEmpty()) {
            throw new IllegalArgumentException("Invalid grant types: " + String.join(", ", invalidGrantTypes));
        }
    }

    private String generateClientSecret() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private OAuth2RegisteredClientEntity toEntityWithCreator(RegisteredClient registeredClient, String createdBy) {
        OAuth2RegisteredClientEntity entity = new OAuth2RegisteredClientEntity();

        LocalDateTime clientIdIssuedAt = Optional.ofNullable(registeredClient.getClientIdIssuedAt())
                .map(d -> LocalDateTime.ofInstant(d, ZoneId.systemDefault())).orElse(null);
        LocalDateTime clientSecretExpiresAt = Optional.ofNullable(registeredClient.getClientSecretExpiresAt())
                .map(d -> LocalDateTime.ofInstant(d, ZoneId.systemDefault())).orElse(null);

        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(clientIdIssuedAt);
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(clientSecretExpiresAt);
        entity.setClientName(registeredClient.getClientName());
        entity.setCreatedBy(createdBy);

        entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(
                registeredClient.getClientAuthenticationMethods().stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .toList()));

        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(
                registeredClient.getAuthorizationGrantTypes().stream()
                        .map(AuthorizationGrantType::getValue)
                        .toList()));

        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));

        try {
            entity.setClientSettings(objectMapper.writeValueAsString(registeredClient.getClientSettings()));
            entity.setTokenSettings(objectMapper.writeValueAsString(registeredClient.getTokenSettings()));
        } catch (Exception e) {
            throw new RuntimeException("Error serializing client settings", e);
        }

        return entity;
    }

    private ClientRegistrationResponse createResponse(RegisteredClient client, String plainSecret, String createdBy) {

        LocalDateTime clientIdIssuedAt = Optional.ofNullable(client.getClientIdIssuedAt())
                .map(d -> LocalDateTime.ofInstant(d, ZoneId.systemDefault())).orElse(null);
        LocalDateTime clientSecretExpiresAt = Optional.ofNullable(client.getClientSecretExpiresAt())
                .map(d -> LocalDateTime.ofInstant(d, ZoneId.systemDefault())).orElse(null);

        ClientRegistrationResponse response = new ClientRegistrationResponse();
        response.setId(client.getId());
        response.setClientId(client.getClientId());
        response.setClientSecret(plainSecret); // Plain secret только при создании
        response.setClientName(client.getClientName());
        response.setClientIdIssuedAt(clientIdIssuedAt);
        response.setClientSecretExpiresAt(clientSecretExpiresAt);
        response.setGrantTypes(client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet()));
        response.setScopes(client.getScopes());
        response.setRedirectUris(client.getRedirectUris());
        response.setRequireProofKey(client.getClientSettings().isRequireProofKey());
        response.setRequireAuthorizationConsent(client.getClientSettings().isRequireAuthorizationConsent());
        response.setReuseRefreshTokens(client.getTokenSettings().isReuseRefreshTokens());
        response.setCreatedBy(createdBy);
        return response;
    }

    @Transactional(readOnly = true)
    public ClientRegistrationResponse getClientById(String clientId, Authentication authentication) {
        OAuth2RegisteredClientEntity entity = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not found: " + clientId));

        // Проверяем права доступа
        validateClientAccess(entity, authentication);

        return entityToResponse(entity);
    }

    @Transactional
    public ClientRegistrationResponse updateClient(String clientId, ClientRegistrationRequest request, Authentication authentication) {
        OAuth2RegisteredClientEntity existingEntity = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("Client not found: " + clientId));

        // Проверяем права доступа
        validateClientAccess(existingEntity, authentication);

        // Проверяем права пользователя на изменение
        validateUserPermissions(authentication, request.getScopes());

        // Проверяем grant types
        validateGrantTypes(request.getGrantTypes());

        // Если clientId изменился, проверяем уникальность
        if (!clientId.equals(request.getClientId()) &&
                registeredClientRepository.existsByClientId(request.getClientId())) {
            throw new IllegalArgumentException("Client ID already exists: " + request.getClientId());
        }

        // Обновляем данные
        updateEntityFromRequest(existingEntity, request);

        // Сохраняем изменения
        clientRepository.save(existingEntity);

        log.info("Updated client: {} by user: {}", clientId, authentication.getName());

        return entityToResponse(existingEntity);
    }

    private void validateClientAccess(OAuth2RegisteredClientEntity entity, Authentication authentication) {
        if ("system".equals(entity.getCreatedBy())) {
            throw new IllegalArgumentException("Cannot modify system client");
        }

        // Проверяем права (только ADMIN может изменять любые клиенты)
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(auth -> "ROLE_ADMIN".equals(auth.getAuthority()));

        if (!isAdmin && !authentication.getName().equals(entity.getCreatedBy())) {
            throw new IllegalArgumentException("Access denied: can only modify own clients");
        }
    }

    private void updateEntityFromRequest(OAuth2RegisteredClientEntity entity, ClientRegistrationRequest request) {
        entity.setClientId(request.getClientId());
        entity.setClientName(request.getClientName());

        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(request.getGrantTypes()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(request.getScopes()));

        if (request.getRedirectUris() != null) {
            entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(request.getRedirectUris()));
        }

        // Обновляем настройки клиента
        ClientSettings clientSettings = ClientSettings.builder()
                .requireAuthorizationConsent(request.getRequireAuthorizationConsent())
                .requireProofKey(request.getRequireProofKey())
                .build();

        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder()
                .reuseRefreshTokens(request.getReuseRefreshTokens());

        long tokenTtlSeconds = request.getAccessTokenTtlSeconds() != null ? request.getAccessTokenTtlSeconds() : defTokenTtl;
        tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(Math.min(maxTokenTtl, tokenTtlSeconds)));

        Duration refreshTtlDaysDuration = Duration.ofDays(refreshTtlDays);

        long refreshTokenTtlSeconds = request.getRefreshTokenTtlSeconds() != null ? request.getRefreshTokenTtlSeconds() : refreshTtlDaysDuration.toSeconds();
        tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtlSeconds));

        try {
            entity.setClientSettings(objectMapper.writeValueAsString(clientSettings));
            entity.setTokenSettings(objectMapper.writeValueAsString(tokenSettingsBuilder.build()));
        } catch (Exception e) {
            throw new RuntimeException("Error serializing client settings", e);
        }

        entity.setUpdatedAt(LocalDateTime.now());
    }

    private void makeServiceUser(String clientId, String clientName, String clientSecret) {
        UserEntity user = new UserEntity();
        user.setUsername(clientId);
        user.setDisplayName(clientName);
        user.setEmail(clientId + "@rightsflow.me");
        user.setPasswordHash(passwordEncoder.encode(clientSecret));
        user.setEnabled(true);
        user.setAccountNonExpired(true);
        user.setAccountNonLocked(true);
        user.setExpirationDate(null);
        user.setLastLogon(null);
        user.setUserType("SERVICE");
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
        log.info("Created service user: {}", user.getUsername());
    }

}
