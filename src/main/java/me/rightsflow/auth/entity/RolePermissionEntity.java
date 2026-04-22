package me.rightsflow.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * JPA-сущность для join-таблицы role_permissions.
 *
 * <p>Выделена в отдельный entity (вместо простого @JoinTable) потому что
 * таблица содержит дополнительные колонки: granted_at и granted_by.</p>
 *
 * <p>Составной первичный ключ (role_id, permission_id) моделируется
 * через вложенный @Embeddable класс {@link RolePermissionId}.</p>
 */
@Entity
@Table(name = "role_permissions")
@Data
@NoArgsConstructor
public class RolePermissionEntity {

    @EmbeddedId
    private RolePermissionId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("roleId")
    @JoinColumn(name = "role_id")
    private RoleEntity role;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("permissionId")
    @JoinColumn(name = "permission_id")
    private PermissionEntity permission;

    @Column(name = "granted_at", nullable = false, updatable = false)
    private LocalDateTime grantedAt = LocalDateTime.now();

    /**
     * Username администратора, назначившего право.
     * "system" — для прав, назначенных при инициализации БД.
     */
    @Column(name = "granted_by", length = 50)
    private String grantedBy;

    public RolePermissionEntity(RoleEntity role, PermissionEntity permission, String grantedBy) {
        this.id = new RolePermissionId(role.getId(), permission.getId());
        this.role = role;
        this.permission = permission;
        this.grantedBy = grantedBy;
        this.grantedAt = LocalDateTime.now();
    }

    // ---- Составной ключ ----

    @Embeddable
    @Data
    @NoArgsConstructor
    public static class RolePermissionId implements java.io.Serializable {

        @Column(name = "role_id")
        private Integer roleId;

        @Column(name = "permission_id")
        private Integer permissionId;

        public RolePermissionId(Integer roleId, Integer permissionId) {
            this.roleId = roleId;
            this.permissionId = permissionId;
        }
    }
}
