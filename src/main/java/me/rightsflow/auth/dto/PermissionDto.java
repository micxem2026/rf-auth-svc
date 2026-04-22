package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class PermissionDto {

    private Integer id;

    @NotBlank(message = "Service name is required")
    @Pattern(
        regexp = "^[a-zA-Z0-9_-]+$",
        message = "Service name can only contain letters, digits, hyphens and underscores"
    )
    private String service;

    @NotBlank(message = "Resource name is required")
    @Pattern(
        regexp = "^[a-zA-Z0-9_]+$",
        message = "Resource name can only contain letters, digits and underscores"
    )
    private String resource;

    @NotBlank(message = "Action name is required")
    @Pattern(
        regexp = "^[a-zA-Z0-9_]+$",
        message = "Action name can only contain letters, digits and underscores"
    )
    private String action;

    private String description;

    private LocalDateTime createdAt;

    /**
     * Полный идентификатор права для отображения в UI.
     * Формируется на клиенте из service + resource + action,
     * но удобно иметь и на сервере для логирования.
     */
    public String getFullName() {
        if (service == null || resource == null || action == null) return null;
        return service + ":" + resource + ":" + action;
    }
}
