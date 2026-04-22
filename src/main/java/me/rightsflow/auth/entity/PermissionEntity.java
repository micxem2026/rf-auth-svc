package me.rightsflow.auth.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(
    name = "permissions",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_permissions_service_resource_action",
        columnNames = {"service", "resource", "action"}
    )
)
@Data
@EqualsAndHashCode(exclude = "roles")
@ToString(exclude = "roles")
public class PermissionEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, length = 100)
    private String service;

    @Column(nullable = false, length = 100)
    private String resource;

    @Column(nullable = false, length = 100)
    private String action;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Роли, которым назначено это право.
     * Маппинг через join table role_permissions.
     */
    @ManyToMany(mappedBy = "permissions")
    private Set<RoleEntity> roles = new HashSet<>();

    /**
     * Возвращает право в виде строки "resource:action".
     * Используется при формировании ответа для кэша микросервисов.
     */
    public String toPermissionString() {
        return resource + ":" + action;
    }

    /**
     * Возвращает полный идентификатор права "service:resource:action".
     */
    public String toFullPermissionString() {
        return service + ":" + resource + ":" + action;
    }
}
