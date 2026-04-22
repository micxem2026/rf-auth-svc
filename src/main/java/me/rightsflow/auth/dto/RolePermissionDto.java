package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class RolePermissionDto {

    @NotNull(message = "Permission ID is required")
    private Integer permissionId;

    // --- Поля только для чтения (заполняются сервисом при ответе) ---

    private Integer roleId;
    private String roleName;

    private String service;
    private String resource;
    private String action;
    private String description;

    private LocalDateTime grantedAt;
    private String grantedBy;
}
