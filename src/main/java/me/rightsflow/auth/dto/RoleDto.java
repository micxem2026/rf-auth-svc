package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RoleDto {
    private Integer id;
    @NotBlank(message = "Role name is required")
    private String name;
    private String description;
    /**
     * Username создателя роли.
     * "system" — системная роль, не подлежит удалению/изменению PERMISSION_MANAGER.
     */
    private String createdBy;
}

