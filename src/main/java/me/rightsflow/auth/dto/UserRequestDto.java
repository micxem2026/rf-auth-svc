package me.rightsflow.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class UserRequestDto {
    @NotBlank(message = "Username is required")
    private String username;

    @NotBlank(message = "Display name is required")
    private String displayName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    // Пароль опционален при обновлении
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;

    private Boolean enabled = true;
    private Boolean accountNonExpired = true;
    private Boolean accountNonLocked = true;
    private LocalDateTime expirationDate;
    private Set<String> roles;
}

