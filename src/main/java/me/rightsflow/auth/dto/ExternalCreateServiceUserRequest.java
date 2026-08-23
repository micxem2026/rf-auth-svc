package me.rightsflow.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.util.Set;

@Data
@Schema(description = "Запрос на создание нового пользователя")
public class ExternalCreateServiceUserRequest {

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9._-]{3,50}$", message = "Username: 3-50 characters, Latin/numbers/._-")
    @Schema(description = "Логин пользователя")
    private String username; // станет client_id

    @NotBlank
    @Schema(description = "Отображаемое имя пользователя")
    private String displayName; // станет client_name

    @Schema(description = "Список ролей назначаемых пользователю. Может быть пустым.")
    private Set<String> roles; // роли, назначаемые создаваемому пользователю
}