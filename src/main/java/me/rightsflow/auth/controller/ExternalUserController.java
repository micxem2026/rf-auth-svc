package me.rightsflow.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.*;
import me.rightsflow.auth.service.ExternalUserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

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
@PreAuthorize("hasRole('ADMIN') or hasRole('ADMIN_CLIENT')")
public class ExternalUserController {

    private final ExternalUserService externalUserService;

    @GetMapping
    public ResponseEntity<List<ExternalUserDto>> getUsers(Authentication authentication) {
        return ResponseEntity.ok(externalUserService.getUsers(authentication));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getUser(@PathVariable Integer id, Authentication authentication) {
        try {
            return ResponseEntity.ok(externalUserService.getUser(id, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping
    public ResponseEntity<?> createServiceUser(@Valid @RequestBody ExternalCreateServiceUserRequest request,
                                               Authentication authentication) {
        try {
            ClientRegistrationResponse created = externalUserService.createServiceUser(request, authentication);
            return new ResponseEntity<>(created, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Integer id,
                                        @Valid @RequestBody ExternalUpdateUserRequest request,
                                        Authentication authentication) {
        try {
            return ResponseEntity.ok(externalUserService.updateUser(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Integer id, Authentication authentication) {
        try {
            externalUserService.deleteUser(id, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/password")
    public ResponseEntity<?> changePassword(@PathVariable Integer id,
                                            @Valid @RequestBody ExternalChangePasswordRequest request,
                                            Authentication authentication) {
        try {
            externalUserService.changePassword(id, request, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{id}/roles")
    public ResponseEntity<?> assignRoles(@PathVariable Integer id,
                                         @Valid @RequestBody ExternalRoleNamesRequest request,
                                         Authentication authentication) {
        try {
            return ResponseEntity.ok(externalUserService.assignRoles(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{id}/roles/revoke")
    public ResponseEntity<?> revokeRoles(@PathVariable Integer id,
                                         @Valid @RequestBody ExternalRoleNamesRequest request,
                                         Authentication authentication) {
        try {
            return ResponseEntity.ok(externalUserService.revokeRoles(id, request, authentication));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
