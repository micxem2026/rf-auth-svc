package me.rightsflow.auth.dto;

import lombok.Data;

import java.util.Set;

@Data
public class LoginResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    private long expiresIn;
    private String username;
    private String displayName;
    private Set<String> roles;
}
