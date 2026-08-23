package me.rightsflow.auth.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Ответ на POST /api/auth/v1/users — объединяет данные созданного
 * OAuth2-клиента (clientId/clientSecret) и парного SERVICE-пользователя.
 */
@Data
public class ExternalServiceUserResponse {
    private Integer id;
    private String clientId;
    private String clientSecret;
    private String username;
    private String displayName;
    private String email;
    private Boolean enabled;
    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private LocalDateTime expirationDate;
    private LocalDateTime lastLogon;
    private String userType;
    private String createdBy;
    private LocalDateTime createdAt;
    private Set<String> roles;
}