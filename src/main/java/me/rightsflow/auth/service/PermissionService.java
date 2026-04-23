package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.*;
import me.rightsflow.auth.entity.PermissionEntity;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.RolePermissionEntity;
import me.rightsflow.auth.repository.PermissionRepository;
import me.rightsflow.auth.repository.RolePermissionRepository;
import me.rightsflow.auth.repository.RoleRepository;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RoleRepository roleRepository;
    private final KafkaTemplate<String, Object> kafkaTemplate;

    private static final String INVALIDATION_TOPIC = "rf.permissions.invalidated";

    /**
     * Роли, права которых защищены от изменения через UI.
     * ADMIN — системная роль, её нельзя ослабить.
     */
    private static final Set<String> PROTECTED_ROLES = Set.of("ADMIN","SERVICE","PERMISSION_MANAGER");

    /** Сервис авторизации — PERMISSION_MANAGER не может назначать его права ролям */
    private static final String AUTH_SERVICE = "rf-auth-svc";

    /**
     * Проверяет может ли текущий пользователь управлять правами указанной роли.
     * <p>
     * ADMIN — может управлять любыми ролями.
     * PERMISSION_MANAGER — только ролями которые сам создал,
     *                      и не может назначать права rf-auth-svc.
     */
    private void validatePermissionManagerAccess(RoleEntity role,
                                                  Authentication authentication) {
        if (authentication == null) return;

        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) return; // ADMIN может всё

        boolean isPermissionManager = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_PERMISSION_MANAGER"));
        if (!isPermissionManager) {
            throw new org.springframework.security.access.AccessDeniedException(
                    "Недостаточно прав для управления правами ролей.");
        }

        // PERMISSION_MANAGER может управлять только созданными им ролями
        if ("system".equals(role.getCreatedBy()) ||
                !authentication.getName().equals(role.getCreatedBy())) {
            throw new IllegalArgumentException(
                    "Вы можете управлять правами только тех ролей, которые создали сами.");
        }
    }

    /**
     * Проверяет что PERMISSION_MANAGER не назначает права сервиса rf-auth-svc.
     */
    private void validatePermissionNotRestricted(PermissionEntity permission,
                                                   Authentication authentication) {
        if (authentication == null) return;

        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) return;

        if (AUTH_SERVICE.equals(permission.getService())) {
            throw new IllegalArgumentException(
                    "Нельзя назначать права сервиса '" + AUTH_SERVICE +
                    "' через делегированное управление.");
        }
    }

    /**
     * Проверяет что роль не является защищённой и что текущий
     * пользователь не изменяет права своей собственной роли
     * (защита от эскалации привилегий).
     */
    private void validateRoleModificationAllowed(RoleEntity role,
                                                 Authentication authentication) {
        // Защищённые роли нельзя менять никому
        if (PROTECTED_ROLES.contains(role.getName())) {
            throw new IllegalArgumentException(
                    "Права роли '" + role.getName() + "' защищены от изменения. " +
                    "Системные роли нельзя редактировать через интерфейс.");
        }
        // Проверяем права ADMIN / PERMISSION_MANAGER
        validatePermissionManagerAccess(role, authentication);
    }

    // ================================================================
    // CRUD прав (permissions)
    // ================================================================

    @Transactional(readOnly = true)
    public List<PermissionDto> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .sorted(Comparator.comparing(PermissionEntity::getService)
                        .thenComparing(PermissionEntity::getResource)
                        .thenComparing(PermissionEntity::getAction))
                .map(this::toPermissionDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<PermissionDto> getPermissionsByService(String service) {
        return permissionRepository.findByServiceOrderByResourceAscActionAsc(service)
                .stream()
                .map(this::toPermissionDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<String> getDistinctServices() {
        return permissionRepository.findDistinctServices();
    }

    @Transactional
    public PermissionDto createPermission(PermissionDto request) {
        if (permissionRepository.existsByServiceAndResourceAndAction(
                request.getService(), request.getResource(), request.getAction())) {
            throw new IllegalArgumentException(
                    "Permission already exists: " + request.getService() +
                    ":" + request.getResource() + ":" + request.getAction());
        }

        PermissionEntity entity = new PermissionEntity();
        entity.setService(request.getService());
        entity.setResource(request.getResource());
        entity.setAction(request.getAction());
        entity.setDescription(request.getDescription());

        PermissionEntity saved = permissionRepository.save(entity);
        log.info("Created permission: {}", saved.toFullPermissionString());
        return toPermissionDto(saved);
    }

    @Transactional
    public void deletePermission(Integer id) {
        PermissionEntity permission = permissionRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Permission not found with id: " + id));

        // Находим затронутые роли до удаления (для инвалидации кэша)
        Set<String> affectedRoles = permission.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toSet());

        permissionRepository.delete(permission);
        log.info("Deleted permission: {}", permission.toFullPermissionString());

        // Инвалидируем кэш для всех ролей, у которых было это право
        if (!affectedRoles.isEmpty()) {
            publishInvalidationEvent(affectedRoles);
        }
    }

    // ================================================================
    // Назначение/снятие прав с ролей
    // ================================================================

    @Transactional(readOnly = true)
    public List<RolePermissionDto> getRolePermissions(Integer roleId) {
        validateRoleExists(roleId);
        return rolePermissionRepository.findByRoleIdWithPermission(roleId)
                .stream()
                .map(this::toRolePermissionDto)
                .collect(Collectors.toList());
    }

    @Transactional
    public RolePermissionDto assignPermission(Integer roleId,
                                               Integer permissionId,
                                               Authentication authentication) {
        RoleEntity role = findRoleById(roleId);
        validateRoleModificationAllowed(role, authentication);
        PermissionEntity permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Permission not found with id: " + permissionId));

        RolePermissionEntity.RolePermissionId compositeId =
                new RolePermissionEntity.RolePermissionId(roleId, permissionId);

        if (rolePermissionRepository.existsById(compositeId)) {
            throw new IllegalArgumentException(
                    "Permission '" + permission.toFullPermissionString() +
                    "' is already assigned to role '" + role.getName() + "'");
        }

        validatePermissionNotRestricted(permission, authentication);
        String grantedBy = authentication != null ? authentication.getName() : "system";
        RolePermissionEntity rp = new RolePermissionEntity(role, permission, grantedBy);
        rolePermissionRepository.save(rp);

        log.info("Assigned permission '{}' to role '{}' by '{}'",
                permission.toFullPermissionString(), role.getName(), grantedBy);

        publishInvalidationEvent(Set.of(role.getName()));
        return toRolePermissionDto(rp);
    }

    @Transactional
    public void revokePermission(Integer roleId,
                                  Integer permissionId,
                                  Authentication authentication) {
        RoleEntity role = findRoleById(roleId);
        validateRoleModificationAllowed(role, authentication);
        PermissionEntity permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Permission not found with id: " + permissionId));

        RolePermissionEntity.RolePermissionId compositeId =
                new RolePermissionEntity.RolePermissionId(roleId, permissionId);

        if (!rolePermissionRepository.existsById(compositeId)) {
            throw new IllegalArgumentException(
                    "Permission '" + permission.toFullPermissionString() +
                    "' is not assigned to role '" + role.getName() + "'");
        }

        rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permissionId);

        String revokedBy = authentication != null ? authentication.getName() : "system";
        log.info("Revoked permission '{}' from role '{}' by '{}'",
                permission.toFullPermissionString(), role.getName(), revokedBy);

        publishInvalidationEvent(Set.of(role.getName()));
    }

    /**
     * Массовое обновление прав роли — заменяет текущий набор прав новым.
     * Используется в UI при сохранении изменений через чекбоксы.
     *
     * @param roleId            ID роли
     * @param newPermissionIds  новый набор ID прав (полный, не дельта)
     * @param authentication    текущий администратор
     */
    @Transactional
    public void updateRolePermissions(Integer roleId,
                                       Set<Integer> newPermissionIds,
                                       Authentication authentication) {
        RoleEntity role = findRoleById(roleId);
        validateRoleModificationAllowed(role, authentication);
        String updatedBy = authentication != null ? authentication.getName() : "system";

        // Текущие права роли
        List<RolePermissionEntity> current =
                rolePermissionRepository.findByRoleIdWithPermission(roleId);
        Set<Integer> currentIds = current.stream()
                .map(rp -> rp.getPermission().getId())
                .collect(Collectors.toSet());

        // Права для добавления
        Set<Integer> toAdd = new HashSet<>(newPermissionIds);
        toAdd.removeAll(currentIds);

        // Права для снятия
        Set<Integer> toRemove = new HashSet<>(currentIds);
        toRemove.removeAll(newPermissionIds);

        // Добавляем новые права
        for (Integer permId : toAdd) {
            PermissionEntity permission = permissionRepository.findById(permId)
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Permission not found: " + permId));
            validatePermissionNotRestricted(permission, authentication);
            rolePermissionRepository.save(
                    new RolePermissionEntity(role, permission, updatedBy));
        }

        // Снимаем удалённые права
        for (Integer permId : toRemove) {
            rolePermissionRepository.deleteByRoleIdAndPermissionId(roleId, permId);
        }

        log.info("Updated permissions for role '{}' by '{}': added={}, removed={}",
                role.getName(), updatedBy, toAdd.size(), toRemove.size());

        // Инвалидируем кэш только если были реальные изменения
        if (!toAdd.isEmpty() || !toRemove.isEmpty()) {
            publishInvalidationEvent(Set.of(role.getName()));
        }
    }

    /**
     * Проверяет является ли роль защищённой (для UI — блокировка редактирования).
     */
    public boolean isProtectedRole(String roleName) {
        return PROTECTED_ROLES.contains(roleName);
    }

    // ================================================================
    // Загрузка кэша для микросервисов
    // ================================================================

    /**
     * Возвращает права для указанных ролей в рамках конкретного сервиса.
     * Вызывается микросервисами через {@code GET /api/permissions/by-roles}.
     *
     * @param service    spring.application.name микросервиса
     * @param roleNames  имена ролей из JWT токена (без префикса ROLE_)
     */
    @Transactional(readOnly = true)
    public PermissionsByRolesResponse getPermissionsForCache(String service,
                                                              Set<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            return PermissionsByRolesResponse.of(service, Collections.emptyMap());
        }

        List<PermissionRepository.RolePermissionProjection> projections =
                permissionRepository.findPermissionsByServiceAndRoles(service, roleNames);

        // Группируем по roleName → List<"resource:action">
        Map<String, List<String>> result = projections.stream()
                .collect(Collectors.groupingBy(
                        PermissionRepository.RolePermissionProjection::getRoleName,
                        Collectors.mapping(
                                p -> p.getResource() + ":" + p.getAction(),
                                Collectors.toList()
                        )
                ));

        // Гарантируем что все запрошенные роли присутствуют в ответе
        // (пустой список для ролей без прав — кэш не будет запрашивать повторно)
        roleNames.forEach(role -> result.putIfAbsent(role, Collections.emptyList()));

        log.debug("Permissions for service '{}', roles {}: {} entries",
                service, roleNames,
                result.values().stream().mapToInt(List::size).sum());

        return PermissionsByRolesResponse.of(service, result);
    }

    /**
     * Batch upsert прав для микросервиса.
     *
     * <p>Для каждого права из запроса:
     * <ul>
     *   <li>Если право с таким (service, resource, action) уже существует — пропускаем.</li>
     *   <li>Если не существует — создаём.</li>
     * </ul>
     *
     * <p>Операция идемпотентна: повторный вызов не создаёт дублей.</p>
     *
     * @param request batch-запрос от микросервиса
     * @return статистика: сколько создано / сколько уже было
     */
    @Transactional
    public PermissionRegistrationResponse upsertPermissions(
            PermissionRegistrationRequest request) {

        String service = request.getService();
        int created = 0;
        int updated = 0;
        int skipped = 0;

        for (PermissionRegistrationRequest.PermissionEntry entry : request.getPermissions()) {

            Optional<PermissionEntity> existing = permissionRepository
                    .findByServiceAndResourceAndAction(
                            service, entry.getResource(), entry.getAction());

            if (existing.isEmpty()) {
                // Право не существует — создаём
                PermissionEntity entity = new PermissionEntity();
                entity.setService(service);
                entity.setResource(entry.getResource());
                entity.setAction(entry.getAction());
                entity.setDescription(entry.getDescription());
                permissionRepository.save(entity);

                log.info("Auto-registered new permission: {}:{}:{}",
                        service, entry.getResource(), entry.getAction());
                created++;

            } else {
                PermissionEntity entity = existing.get();
                String newDescription = entry.getDescription();
                String oldDescription = entity.getDescription();

                // Сравниваем description: обновляем только если изменилось
                boolean descriptionChanged = !Objects.equals(oldDescription, newDescription);

                if (descriptionChanged) {
                    log.info("Updating description for permission {}:{}:{}: '{}' → '{}'",
                            service, entry.getResource(), entry.getAction(),
                            oldDescription, newDescription);
                    entity.setDescription(newDescription);
                    permissionRepository.save(entity);
                    updated++;
                } else {
                    log.debug("Permission {}:{}:{} already exists, description unchanged. Skipping.",
                            service, entry.getResource(), entry.getAction());
                    skipped++;
                }
            }
        }

        log.info("Batch upsert complete for service '{}': created={}, updated={}, skipped={}",
                service, created, updated, skipped);

        return PermissionRegistrationResponse.builder()
                .service(service)
                .total(request.getPermissions().size())
                .created(created)
                .updated(updated)
                .skipped(skipped)
                .build();
    }

    // ================================================================
    // Kafka
    // ================================================================

    private void publishInvalidationEvent(Set<String> roleNames) {
        Map<String, Object> event = new HashMap<>();
        event.put("role_names", roleNames);
        event.put("changed_at", java.time.Instant.now().toString());

        try {
            kafkaTemplate.send(INVALIDATION_TOPIC, event);
            log.info("Published permission invalidation event for roles: {}", roleNames);
        } catch (Exception e) {
            // Не бросаем — изменение в БД уже произошло.
            // Микросервисы обновят кэш по расписанию.
            log.error("Failed to publish permission invalidation event for roles: {}. " +
                      "Cache will be refreshed on next schedule.", roleNames, e);
        }
    }

    // ================================================================
    // Вспомогательные методы
    // ================================================================

    private RoleEntity findRoleById(Integer roleId) {
        return roleRepository.findById(roleId.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found with id: " + roleId));
    }

    private void validateRoleExists(Integer roleId) {
        if (!roleRepository.existsById(roleId.longValue())) {
            throw new IllegalArgumentException("Role not found with id: " + roleId);
        }
    }

    private PermissionDto toPermissionDto(PermissionEntity entity) {
        PermissionDto dto = new PermissionDto();
        dto.setId(entity.getId());
        dto.setService(entity.getService());
        dto.setResource(entity.getResource());
        dto.setAction(entity.getAction());
        dto.setDescription(entity.getDescription());
        dto.setCreatedAt(entity.getCreatedAt());
        return dto;
    }

    private RolePermissionDto toRolePermissionDto(RolePermissionEntity entity) {
        RolePermissionDto dto = new RolePermissionDto();
        dto.setRoleId(entity.getRole().getId());
        dto.setRoleName(entity.getRole().getName());
        dto.setPermissionId(entity.getPermission().getId());
        dto.setService(entity.getPermission().getService());
        dto.setResource(entity.getPermission().getResource());
        dto.setAction(entity.getPermission().getAction());
        dto.setDescription(entity.getPermission().getDescription());
        dto.setGrantedAt(entity.getGrantedAt());
        dto.setGrantedBy(entity.getGrantedBy());
        return dto;
    }
}
