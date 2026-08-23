package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import java.util.Set;

@Data
public class ExternalCreateServiceUserRequest {

    @NotBlank
    @Pattern(regexp = "^[a-zA-Z0-9._-]{3,50}$", message = "Username: 3-50 символов, латиница/цифры/._-")
    private String username; // станет client_id

    @NotBlank
    private String displayName; // станет client_name

    @NotEmpty
    private Set<String> scopes; // OAuth2-скоупы клиента; scope 'admin' запрещён
}