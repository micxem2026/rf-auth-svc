package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.RolePermissionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermissionEntity, RolePermissionEntity.RolePermissionId> {

    /**
     * Все записи о назначенных правах для конкретной роли.
     * Используется при отображении прав роли в UI.
     */
    @Query("""
        SELECT rp FROM RolePermissionEntity rp
        JOIN FETCH rp.permission
        WHERE rp.role.id = :roleId
        ORDER BY rp.permission.service, rp.permission.resource, rp.permission.action
        """)
    List<RolePermissionEntity> findByRoleIdWithPermission(@Param("roleId") Integer roleId);

    /**
     * Проверка: назначено ли уже данное право данной роли.
     */
    boolean existsById(RolePermissionEntity.RolePermissionId id);

    /**
     * Снятие конкретного права с роли по составному ключу.
     */
    @Modifying
    @Query("""
        DELETE FROM RolePermissionEntity rp
        WHERE rp.role.id = :roleId
          AND rp.permission.id = :permissionId
        """)
    void deleteByRoleIdAndPermissionId(
            @Param("roleId") Integer roleId,
            @Param("permissionId") Integer permissionId);

    /**
     * Снятие всех прав с роли. Используется при удалении роли
     * (дополнительно к каскадному удалению на уровне БД).
     */
    @Modifying
    @Query("DELETE FROM RolePermissionEntity rp WHERE rp.role.id = :roleId")
    void deleteAllByRoleId(@Param("roleId") Integer roleId);
}
