package me.rightsflow.auth.dto;

import lombok.Data;

import java.util.Set;

/**
 * Облегчённое представление пользователя для PERMISSION_MANAGER.
 * Содержит только данные необходимые для назначения ролей —
 * без чувствительных полей (email, даты, статусы блокировки).
 */
@Data
public class UserSummaryDto {
    private Integer id;
    private String username;
    private String displayName;
    private String userType;
    private Set<String> roles;
}
