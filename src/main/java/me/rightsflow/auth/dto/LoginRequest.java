package me.rightsflow.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@Schema(description = "Запрос на получение токена пользователя")
public class LoginRequest {
    @NotBlank
    @Schema(description = "Логин пользователя")
    private String username;

    @NotBlank
    @Schema(description = "Пароль пользователя")
    private String password;
}
