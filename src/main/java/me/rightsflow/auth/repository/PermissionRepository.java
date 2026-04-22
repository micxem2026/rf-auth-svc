package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.PermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface PermissionRepository extends JpaRepository<PermissionEntity, Integer> {

    /**
     * Поиск права по уникальной тройке. Используется при создании
     * для проверки дублей и при назначении права роли.
     */
    Optional<PermissionEntity> findByServiceAndResourceAndAction(
            String service, String resource, String action);

    /**
     * Все права конкретного сервиса. Используется в UI
     * для отображения прав сервиса при настройке ролей.
     */
    List<PermissionEntity> findByServiceOrderByResourceAscActionAsc(String service);

    /**
     * Все уникальные имена сервисов. Используется в UI
     * для построения дерева сервис → контроллер → метод.
     */
    @Query("SELECT DISTINCT p.service FROM PermissionEntity p ORDER BY p.service")
    List<String> findDistinctServices();

    /**
     * Все уникальные ресурсы (контроллеры) конкретного сервиса.
     */
    @Query("SELECT DISTINCT p.resource FROM PermissionEntity p " +
           "WHERE p.service = :service ORDER BY p.resource")
    List<String> findDistinctResourcesByService(@Param("service") String service);

    /**
     * Ключевой запрос для загрузки кэша микросервисами.
     * <p>
     * Возвращает все права для указанных ролей в рамках конкретного сервиса.
     * Результат — проекция (roleName, resource, action) для формирования
     * Map<roleName, Set<"resource:action">> без лишней загрузки объектов.
     */
    @Query("""
        SELECT r.name AS roleName,
               p.resource AS resource,
               p.action AS action
        FROM PermissionEntity p
        JOIN p.roles r
        WHERE p.service = :service
          AND r.name IN :roleNames
        ORDER BY r.name, p.resource, p.action
        """)
    List<RolePermissionProjection> findPermissionsByServiceAndRoles(
            @Param("service") String service,
            @Param("roleNames") Set<String> roleNames);

    /**
     * Все права конкретной роли по всем сервисам.
     * Используется в UI на странице управления ролью.
     */
    @Query("""
        SELECT p FROM PermissionEntity p
        JOIN p.roles r
        WHERE r.id = :roleId
        ORDER BY p.service, p.resource, p.action
        """)
    List<PermissionEntity> findByRoleId(@Param("roleId") Integer roleId);

    /**
     * Проверка существования права по тройке.
     */
    boolean existsByServiceAndResourceAndAction(
            String service, String resource, String action);

    // ---- Проекция для загрузки кэша ----

    interface RolePermissionProjection {
        String getRoleName();
        String getResource();
        String getAction();
    }
}
