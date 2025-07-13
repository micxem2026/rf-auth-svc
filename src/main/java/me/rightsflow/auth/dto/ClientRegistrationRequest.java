package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class ClientRegistrationRequest {

    @NotBlank(message = "Client name is required")
    private String clientName;

    @NotBlank(message = "Client ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]+$", message = "Client ID can only contain letters, numbers, hyphens and underscores")
    private String clientId;

    @NotEmpty(message = "At least one grant type is required")
    private Set<String> grantTypes;

    @NotEmpty(message = "At least one scope is required")
    private Set<String> scopes;

    private Set<String> redirectUris;

    private Long clientSecretExpiresInDays;

    private Long accessTokenTtlSeconds;

    private Long refreshTokenTtlSeconds;

    private Boolean requireAuthorizationConsent = false;

    private Boolean requireProofKey = false;

    private Boolean reuseRefreshTokens = true;

    public LocalDateTime getClientSecretExpiresAt() {
        if (clientSecretExpiresInDays != null && clientSecretExpiresInDays > 0) {
            return LocalDateTime.now().plusSeconds(clientSecretExpiresInDays * 24 * 60 * 60);
        }
        return null;
    }

    private Boolean isUpdate = false;

}