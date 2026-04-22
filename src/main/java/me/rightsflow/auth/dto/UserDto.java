package me.rightsflow.auth.dto;

import lombok.Data;

import java.time.LocalDateTime;
import java.util.Set;

@Data
public class UserDto {
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
    private Set<String> roles;
    /**
     * true — пользователь является системным, его нельзя удалить или отключить.
     * Заполняется в UserService на основе PROTECTED_USERNAMES.
     */
    private Boolean protectedUser = false;
}

