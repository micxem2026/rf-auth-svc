package me.rightsflow.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
@Schema(description = "Запрос на назначение/снятие ролей пользователя")
public class ExternalRoleNamesRequest {
    @NotEmpty
    @Schema(description = "Список ролей")
    private Set<String> roles;
}
