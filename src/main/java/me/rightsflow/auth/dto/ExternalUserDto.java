package me.rightsflow.auth.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class ExternalUserDto {
    private Integer id;
    private String username;
    private String displayName;
    private String email;
    private Boolean enabled;
    private Boolean accountNonExpired;
    private Boolean accountNonLocked;
    private LocalDateTime expirationDate;
    private LocalDateTime lastLogon;
    private String userType;
    private String createdBy;
    private LocalDateTime createdAt;
    private Set<String> roles;
}
