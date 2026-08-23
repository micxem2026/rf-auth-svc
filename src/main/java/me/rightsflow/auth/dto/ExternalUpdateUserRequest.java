package me.rightsflow.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Schema(description = "Запрос на изменение пользователя")
public class ExternalUpdateUserRequest {

    @NotBlank
    @Schema(description = "Отображаемое имя пользователя")
    private String displayName;

    @NotBlank
    @Email
    @Schema(description = "Email пользователя")
    private String email;

    @NotNull
    @Schema(description = "Включён ли пользователь (true — активен, false — учётная запись отключена)")
    private Boolean enabled;

    @NotNull
    @Schema(description = "Не истёк ли срок действия аккаунта (true — аккаунт действителен; " +
            "false — принудительно считать аккаунт просроченным независимо от expirationDate). " +
            "Итоговая проверка: accountNonExpired И (expirationDate не задана ИЛИ ещё не наступила).")
    private Boolean accountNonExpired;

    @NotNull
    @Schema(description = "Не заблокирован ли аккаунт (true — не заблокирован; false — аккаунт заблокирован)")
    private Boolean accountNonLocked;

    @Schema(description = "Дата истечения срока действия аккаунта (null — без ограничения по сроку)")
    private LocalDateTime expirationDate;
}
