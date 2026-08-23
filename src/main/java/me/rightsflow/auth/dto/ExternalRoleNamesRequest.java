package me.rightsflow.auth.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.Set;

@Data
public class ExternalRoleNamesRequest {
    @NotEmpty
    private Set<String> roles;
}
