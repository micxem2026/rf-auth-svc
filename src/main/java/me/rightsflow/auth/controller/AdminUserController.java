package me.rightsflow.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.RoleDto;
import me.rightsflow.auth.dto.UserDto;
import me.rightsflow.auth.dto.UserRequestDto;
import me.rightsflow.auth.dto.UserSummaryDto;
import me.rightsflow.auth.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin/api")
@RequiredArgsConstructor
@Slf4j
public class AdminUserController {

    private final UserService userService;

    // --- User Endpoints ---

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserDto>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    /**
     * Облегчённый список пользователей для вкладки назначения ролей.
     * Доступен PERMISSION_MANAGER — не содержит чувствительных данных.
     */
    @GetMapping("/users/summary")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<List<UserSummaryDto>> getUsersSummary() {
        return ResponseEntity.ok(userService.getAllUsersSummary());
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUserById(@PathVariable Integer id) {
        try {
            return ResponseEntity.ok(userService.getUserById(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createUser(@Valid @RequestBody UserRequestDto request) {
        try {
            UserDto createdUser = userService.createUser(request);
            return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUser(@PathVariable Integer id, @Valid @RequestBody UserRequestDto request) {
        try {
            UserDto updatedUser = userService.updateUser(id, request);
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Integer id) {
        try {
            userService.deleteUser(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // --- Role Endpoints ---

    @GetMapping("/roles")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<List<RoleDto>> getAllRoles() {
        return ResponseEntity.ok(userService.getAllRoles());
    }

    @PostMapping("/roles")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> createRole(@Valid @RequestBody RoleDto request,
                                        Authentication authentication) {
        try {
            request.setCreatedBy(authentication.getName());
            //noinspection java:S5131
            // False positive: ответ сериализуется Jackson в application/json,
            // не в HTML-контекст. JSON не является XSS-sink.
            // @Valid на входе гарантирует что поля прошли валидацию по @Pattern.
            RoleDto createdRole = userService.createRole(request);
            return new ResponseEntity<>(createdRole, HttpStatus.CREATED);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/roles/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> deleteRole(@PathVariable Integer id,
                                        Authentication authentication) {
        try {
            userService.deleteRole(id, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Назначить роль пользователю.
     * ADMIN — может назначать любую роль.
     * PERMISSION_MANAGER — только роли которые он сам создал.
     */
    @PostMapping("/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> assignRoleToUser(@PathVariable Integer userId,
                                              @PathVariable Integer roleId,
                                              Authentication authentication) {
        try {
            UserDto updated = userService.assignRoleToUser(userId, roleId, authentication);
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Снять роль с пользователя.
     * ADMIN — может снимать любую роль.
     * PERMISSION_MANAGER — только роли которые он сам создал.
     */
    @DeleteMapping("/users/{userId}/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> revokeRoleFromUser(@PathVariable Integer userId,
                                                @PathVariable Integer roleId,
                                                Authentication authentication) {
        try {
            UserDto updated = userService.revokeRoleFromUser(userId, roleId, authentication);
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }


}

