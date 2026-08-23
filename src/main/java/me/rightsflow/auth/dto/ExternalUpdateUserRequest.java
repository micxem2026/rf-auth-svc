package me.rightsflow.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class ExternalUpdateUserRequest {

    @NotBlank
    private String displayName;

    @NotBlank
    @Email
    private String email;

    @NotNull
    private Boolean enabled;

    @NotNull
    private Boolean accountNonExpired;

    @NotNull
    private Boolean accountNonLocked;

    private LocalDateTime expirationDate;
}
