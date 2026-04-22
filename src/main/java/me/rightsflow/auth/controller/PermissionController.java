package me.rightsflow.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.PermissionDto;
import me.rightsflow.auth.dto.PermissionsByRolesResponse;
import me.rightsflow.auth.dto.RolePermissionDto;
import me.rightsflow.auth.service.PermissionService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * REST-контроллер для управления правами доступа.
 *
 * <p>Два типа клиентов:</p>
 * <ul>
 *   <li>Веб-интерфейс администратора — CRUD прав и назначение ролям</li>
 *   <li>Микросервисы — загрузка кэша через {@code GET /api/permissions/by-roles}</li>
 * </ul>
 *
 * <p>Доступ к административным эндпоинтам ограничен ролью ADMIN.
 * Эндпоинт загрузки кэша доступен любому аутентифицированному запросу
 * (микросервисы используют client_credentials с токеном системного клиента).</p>
 */
@RestController
@RequestMapping("/api/permissions")
@RequiredArgsConstructor
@Slf4j
public class PermissionController {

    private final PermissionService permissionService;

    // ================================================================
    // Эндпоинт для загрузки кэша микросервисами
    // Доступен любому аутентифицированному клиенту (не только ADMIN)
    // ================================================================

    /**
     * Загрузка прав для кэша микросервиса.
     *
     * <p>Вызывается из rf-common-lib при старте микросервиса и при инвалидации кэша.
     * Возвращает права только для запрошенного сервиса.</p>
     *
     * <p>Пример запроса:
     * {@code GET /api/permissions/by-roles?roles=MANAGER,VIEWER&service=rf-contract-svc}</p>
     */
    @GetMapping("/by-roles")
    public ResponseEntity<PermissionsByRolesResponse> getPermissionsByRoles(
            @RequestParam String service,
            @RequestParam Set<String> roles) {

        log.debug("Permissions cache request: service='{}', roles={}", service, roles);
        PermissionsByRolesResponse response = permissionService.getPermissionsForCache(service, roles);
        return ResponseEntity.ok(response);
    }

    // ================================================================
    // CRUD прав — только ADMIN
    // ================================================================

    /**
     * Список всех прав. Для UI главной страницы управления правами.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PermissionDto>> getAllPermissions() {
        return ResponseEntity.ok(permissionService.getAllPermissions());
    }

    /**
     * Права конкретного сервиса. Используется в UI при фильтрации по сервису.
     */
    @GetMapping("/by-service")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<PermissionDto>> getPermissionsByService(
            @RequestParam String service) {
        return ResponseEntity.ok(permissionService.getPermissionsByService(service));
    }

    /**
     * Список всех сервисов, для которых зарегистрированы права.
     * Используется в UI для построения фильтра/дерева.
     */
    @GetMapping("/services")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<String>> getDistinctServices() {
        return ResponseEntity.ok(permissionService.getDistinctServices());
    }

    /**
     * Создание нового права.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createPermission(
            @Valid @RequestBody PermissionDto request) {
        try {
            //noinspection java:S5131
            // False positive: ответ сериализуется Jackson в application/json,
            // не в HTML-контекст. JSON не является XSS-sink.
            // @Valid на входе гарантирует что поля прошли валидацию по @Pattern.
            PermissionDto created = permissionService.createPermission(request);
            log.info("Permission created: {}", created.getFullName());
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Удаление права. Автоматически снимает право со всех ролей
     * (каскадное удаление в БД) и инвалидирует кэш.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deletePermission(@PathVariable Integer id) {
        try {
            permissionService.deletePermission(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ================================================================
    // Управление правами роли — только ADMIN
    // ================================================================

    /**
     * Права конкретной роли. Используется в UI при открытии страницы роли.
     */
    @GetMapping("/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> getRolePermissions(@PathVariable Integer roleId) {
        try {
            return ResponseEntity.ok(permissionService.getRolePermissions(roleId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Назначение одного права роли.
     */
    @PostMapping("/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> assignPermission(
            @PathVariable Integer roleId,
            @Valid @RequestBody RolePermissionDto request,
            Authentication authentication) {
        try {
            RolePermissionDto result = permissionService.assignPermission(
                    roleId, request.getPermissionId(), authentication);
            return ResponseEntity.status(HttpStatus.CREATED).body(result);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Снятие одного права с роли.
     */
    @DeleteMapping("/roles/{roleId}/{permissionId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> revokePermission(
            @PathVariable Integer roleId,
            @PathVariable Integer permissionId,
            Authentication authentication) {
        try {
            permissionService.revokePermission(roleId, permissionId, authentication);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Массовое обновление прав роли (используется в UI при сохранении через чекбоксы).
     * Принимает полный новый набор ID прав — вычисляет и применяет дельту.
     */
    @PutMapping("/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public ResponseEntity<?> updateRolePermissions(
            @PathVariable Integer roleId,
            @RequestBody Set<Integer> permissionIds,
            Authentication authentication) {
        try {
            permissionService.updateRolePermissions(roleId, permissionIds, authentication);
            return ResponseEntity.ok(permissionService.getRolePermissions(roleId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
