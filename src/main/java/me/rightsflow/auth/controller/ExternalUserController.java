package me.rightsflow.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.*;
import me.rightsflow.auth.service.ExternalUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Внешнее API для admin_client (user_type='USER', роль ADMIN_CLIENT).
 * ADMIN имеет полный доступ ко всем пользователям, ADMIN_CLIENT — только
 * к тем SERVICE-пользователям, которых создал сам (проверяется в сервисе
 * по полю users.created_by).
 */
@RestController
@RequestMapping("/api/auth/v1/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Пользователи", description = "Получение и управление пользователями")
public class ExternalUserController {

    private final ExternalUserService externalUserService;

    /** Роли, которым разрешён вызов методов внешнего API. */
    private static final Set<String> ALLOWED_ROLES = Set.of("ROLE_ADMIN", "ROLE_ADMIN_CLIENT");

    private void checkAccess(Authentication authentication) {
        boolean allowed = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(ALLOWED_ROLES::contains);
        if (!allowed) {
            throw new AccessDeniedException(
                    "Доступ запрещён: требуется роль ADMIN или ADMIN_CLIENT.");
        }
    }

    @GetMapping("/available-roles")
    @Operation(summary = "Получение списка доступных ролей")
    public ResponseEntity<List<RoleDto>> getAvailableRoles(Authentication authentication) {
        checkAccess(authentication);
        return ResponseEntity.ok(externalUserService.getAssignableRoles(authentication));
    }

    @GetMapping
    @Operation(summary = "Получение списка доступных пользователей")
    public ResponseEntity<List<ExternalUserDto>> getUsers(Authentication authentication) {
        checkAccess(authentication);
        return ResponseEntity.ok(externalUserService.getUsers(authentication));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Получение пользователя по заданному ID")
    public ResponseEntity<?> getUser(@Parameter(description = "ID пользователя")
                                     @PathVariable Integer id, Authentication authentication) {
        checkAccess(authentication);
        try {
            return ResponseEntity.ok(externalUserService.getUser(id, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping
    @Operation(summary = "Создание нового пользователя")
    public ResponseEntity<?> createServiceUser(@Valid @RequestBody ExternalCreateServiceUserRequest request,
                                               Authentication authentication) {
        checkAccess(authentication);
        try {
            ExternalServiceUserResponse created = externalUserService.createServiceUser(request, authentication);
            return new ResponseEntity<>(created, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    @Operation(summary = "Изменение пользователя")
    public ResponseEntity<?> updateUser(@Parameter(description = "ID пользователя")
                                        @PathVariable Integer id,
                                        @Valid @RequestBody ExternalUpdateUserRequest request,
                                        Authentication authentication) {
        checkAccess(authentication);
        try {
            return ResponseEntity.ok(externalUserService.updateUser(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Удаление пользователя")
    public ResponseEntity<?> deleteUser(@Parameter(description = "ID пользователя")
                                        @PathVariable Integer id, Authentication authentication) {
        checkAccess(authentication);
        try {
            externalUserService.deleteUser(id, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/password")
    @Operation(summary = "Изменение пароля пользователя")
    public ResponseEntity<?> changePassword(@Parameter(description = "ID пользователя")
                                            @PathVariable Integer id,
                                            @Valid @RequestBody ExternalChangePasswordRequest request,
                                            Authentication authentication) {
        checkAccess(authentication);
        try {
            externalUserService.changePassword(id, request, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{id}/roles")
    @Operation(summary = "Назначение ролей пользователю")
    public ResponseEntity<?> assignRoles(@Parameter(description = "ID пользователя")
                                         @PathVariable Integer id,
                                         @Valid @RequestBody ExternalRoleNamesRequest request,
                                         Authentication authentication) {
        checkAccess(authentication);
        try {
            return ResponseEntity.ok(externalUserService.assignRoles(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{id}/roles/revoke")
    @Operation(summary = "Снятие ролей с пользователя")
    public ResponseEntity<?> revokeRoles(@Parameter(description = "ID пользователя")
                                         @PathVariable Integer id,
                                         @Valid @RequestBody ExternalRoleNamesRequest request,
                                         Authentication authentication) {
        checkAccess(authentication);
        try {
            return ResponseEntity.ok(externalUserService.revokeRoles(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}