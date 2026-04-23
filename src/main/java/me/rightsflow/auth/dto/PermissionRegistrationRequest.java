package me.rightsflow.auth.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.util.List;

/**
 * DTO для batch upsert прав, поступающего от микросервисов при старте.
 *
 * <p>Эндпоинт: {@code POST /api/permissions/register-batch}.</p>
 * <p>Доступен любому аутентифицированному системному клиенту
 * (client_credentials с токеном системного клиента).</p>
 */
@Data
public class PermissionRegistrationRequest {

    @NotBlank(message = "Service name is required")
    @Pattern(
            regexp = "^[a-zA-Z0-9_-]+$",
            message = "Service name can only contain letters, digits, hyphens and underscores"
    )
    private String service;

    @NotEmpty(message = "Permissions list must not be empty")
    @Valid
    private List<PermissionEntry> permissions;

    @Data
    public static class PermissionEntry {

        @NotBlank(message = "Resource is required")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$",
                message = "Resource can only contain letters, digits and underscores")
        private String resource;

        @NotBlank(message = "Action is required")
        @Pattern(regexp = "^[a-zA-Z0-9_]+$",
                message = "Action can only contain letters, digits and underscores")
        private String action;

        private String description;
    }
}


