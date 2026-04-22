package me.rightsflow.auth.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class ClientRegistrationResponse {
    private String id;
    private String clientId;
    private String clientSecret;
    private String clientName;
    private LocalDateTime clientIdIssuedAt;
    private LocalDateTime clientSecretExpiresAt;
    private Set<String> grantTypes;
    private Set<String> scopes;
    private Set<String> redirectUris;
    private Boolean requireAuthorizationConsent;
    private Boolean requireProofKey;
    private Boolean reuseRefreshTokens;
    private String createdBy;
    private LocalDateTime createdAt;

    /**
     * Флаг защиты от удаления и изменения через веб-интерфейс.
     * true — кнопки "Изменить" и "Удалить" скрываются в UI.
     */
    private Boolean protectedClient = false;
}
