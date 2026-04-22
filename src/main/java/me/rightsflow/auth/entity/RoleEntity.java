package me.rightsflow.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "roles")
@Data
@EqualsAndHashCode(exclude = {"users", "permissions"})
@ToString(exclude = {"users", "permissions"})
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false, length = 50)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Username пользователя, создавшего роль.
     * "system" — роль создана при инициализации, нельзя удалить/изменить.
     */
    @Column(name = "created_by", nullable = false, length = 50)
    private String createdBy = "system";

    @ManyToMany(mappedBy = "roles")
    private Set<UserEntity> users = new HashSet<>();

    /**
     * Права, назначенные этой роли.
     *
     * <p>Связь через join-таблицу role_permissions.
     * EAGER загрузка оправдана: права роли нужны при каждой проверке аутентификации,
     * а их количество ограничено (десятки, не тысячи).</p>
     *
     * <p>Запись осуществляется через {@link RolePermissionEntity} напрямую
     * (для сохранения granted_by), поэтому здесь только чтение (insertable=false, updatable=false).</p>
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "role_permissions",
        joinColumns = @JoinColumn(name = "role_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id", insertable = false, updatable = false)
    )
    private Set<PermissionEntity> permissions = new HashSet<>();
}
