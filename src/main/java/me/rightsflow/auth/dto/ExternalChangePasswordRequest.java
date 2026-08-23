package me.rightsflow.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Смена пароля пользователя.
 * <p>Для SERVICE-пользователей (у которых есть парный OAuth2-клиент)
 * новое значение также становится client_secret этого клиента —
 * пароль и client_secret для SERVICE-аккаунта являются одним и тем же
 * секретом, хранящимся в двух местах.</p>
 */
@Data
@Schema(description = "Запрос на изменение пароля пользователя")
public class ExternalChangePasswordRequest {
    @NotBlank
    @Size(min = 20, max = 100)
    @Schema(description = "Новый пароль пользователя")
    private String newPassword;
}
