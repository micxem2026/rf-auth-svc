package me.rightsflow.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.entity.OAuth2RegisteredClientEntity;
import me.rightsflow.auth.repository.OAuth2RegisteredClientRepository;
import org.apache.http.auth.Credentials;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@Slf4j
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2RegisteredClientRepository clientRepository;
    private final ObjectMapper objectMapper;

    @Autowired
    public JpaRegisteredClientRepository(OAuth2RegisteredClientRepository clientRepository,
                                         @Qualifier("securityObjectMapper") ObjectMapper objectMapper) {
        this.clientRepository = clientRepository;
        this.objectMapper = objectMapper;
/*        this.objectMapper = objectMapper.copy();

        // Получаем ClassLoader, который видит классы Spring Security
        ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();

        // Находим и регистрируем все необходимые модули для десериализации классов Spring Security
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);*/
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");

        OAuth2RegisteredClientEntity entity = toEntity(registeredClient);
        clientRepository.save(entity);

        log.info("Saved registered client: {}", registeredClient.getClientId());
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return clientRepository.findById(id).map(this::toRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return clientRepository.findByClientId(clientId).map(this::toRegisteredClient).orElse(null);
    }

    public List<RegisteredClient> findUserCreatedClients() {
        return clientRepository.findUserCreatedClients()
                .stream()
                .map(this::toRegisteredClient)
                .toList();
    }

    public List<RegisteredClient> findSystemClients() {
        return clientRepository.findSystemClients()
                .stream()
                .map(this::toRegisteredClient)
                .toList();
    }

    public void deleteByClientId(String clientId) {
        clientRepository.findByClientId(clientId)
                .ifPresent(entity -> {
                    if (!"system".equals(entity.getCreatedBy())) {
                        clientRepository.delete(entity);
                        log.info("Deleted registered client: {}", clientId);
                    } else {
                        log.warn("Attempt to delete system client: {}", clientId);
                        throw new IllegalArgumentException("Cannot delete system client");
                    }
                });
    }

    public boolean existsByClientId(String clientId) {
        return clientRepository.existsByClientId(clientId);
    }

    private OAuth2RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OAuth2RegisteredClientEntity entity = new OAuth2RegisteredClientEntity();
        if (authentication != null && authentication.getPrincipal() instanceof Credentials credentials) {
            entity.setCreatedBy(credentials.getUserPrincipal().getName());
            log.debug("==> Found credentials for user: {}", credentials.getUserPrincipal().getName());
        }

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

    private RegisteredClient toRegisteredClient(OAuth2RegisteredClientEntity entity) {
        Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(entity.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes());
        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(entity.getRedirectUris());
        Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(entity.getPostLogoutRedirectUris());
        Set<String> scopes = StringUtils.commaDelimitedListToSet(entity.getScopes());

        Instant clientIdIssuedAt = Optional.ofNullable(entity.getClientIdIssuedAt())
                .map(d -> d.atZone(ZoneId.systemDefault()).toInstant()).orElse(null);
        Instant clientSecretExpiresAt = Optional.ofNullable(entity.getClientSecretExpiresAt())
                .map(d -> d.atZone(ZoneId.systemDefault()).toInstant()).orElse(null);

        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientIdIssuedAt(clientIdIssuedAt)
                .clientSecret(entity.getClientSecret())
                .clientSecretExpiresAt(clientSecretExpiresAt)
                .clientName(entity.getClientName());

        clientAuthenticationMethods.forEach(method ->
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(method)));

        authorizationGrantTypes.forEach(grantType ->
                builder.authorizationGrantType(new AuthorizationGrantType(grantType)));

        redirectUris.forEach(builder::redirectUri);
        postLogoutRedirectUris.forEach(builder::postLogoutRedirectUri);
        scopes.forEach(builder::scope);

        try {

            ClientSettings clientSettings = objectMapper.readValue(entity.getClientSettings(), ClientSettings.class);
            TokenSettings tokenSettings = objectMapper.readValue(entity.getTokenSettings(), TokenSettings.class);

            builder.clientSettings(clientSettings);
            builder.tokenSettings(tokenSettings);

        } catch (Exception e) {
            throw new RuntimeException("Error deserializing client settings", e);
        }

        return builder.build();
    }
}

