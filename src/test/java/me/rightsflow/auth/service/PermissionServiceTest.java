package me.rightsflow.auth.service;

import me.rightsflow.auth.entity.PermissionEntity;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.RolePermissionEntity;
import me.rightsflow.auth.repository.PermissionRepository;
import me.rightsflow.auth.repository.RolePermissionRepository;
import me.rightsflow.auth.repository.RoleRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("PermissionService")
class PermissionServiceTest {

    @Mock PermissionRepository permissionRepository;
    @Mock RolePermissionRepository rolePermissionRepository;
    @Mock RoleRepository roleRepository;
    @Mock KafkaTemplate<String, Object> kafkaTemplate;

    @InjectMocks PermissionService permissionService;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private RoleEntity makeRole(Integer id, String name, String createdBy) {
        RoleEntity r = new RoleEntity();
        r.setId(id);
        r.setName(name);
        r.setCreatedBy(createdBy);
        r.setUsers(new HashSet<>());
        r.setPermissions(new HashSet<>());
        return r;
    }

    private PermissionEntity makePermission(Integer id, String service,
                                             String resource, String action) {
        PermissionEntity p = new PermissionEntity();
        p.setId(id);
        p.setService(service);
        p.setResource(resource);
        p.setAction(action);
        p.setRoles(new HashSet<>());
        return p;
    }

    private Authentication adminAuth() {
        return new UsernamePasswordAuthenticationToken("admin", null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private Authentication pmAuth(String username) {
        return new UsernamePasswordAuthenticationToken(username, null,
                List.of(new SimpleGrantedAuthority("ROLE_PERMISSION_MANAGER")));
    }

    private Authentication managerAuth() {
        return new UsernamePasswordAuthenticationToken("user1", null,
                List.of(new SimpleGrantedAuthority("ROLE_MANAGER")));
    }

    // ----------------------------------------------------------------
    // validateRoleModificationAllowed — через assignPermission
    // ----------------------------------------------------------------

    @Nested @DisplayName("Защита роли ADMIN от изменения")
    class ProtectedRoleGuard {

        @Test
        @DisplayName("Запрещает изменять права роли ADMIN кому угодно")
        void preventsModifyingAdminRole() {
            RoleEntity adminRole = makeRole(1, "ADMIN", "system");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(adminRole));
            // permissionRepository не стабируем — исключение бросается до его вызова

            assertThatThrownBy(() ->
                    permissionService.assignPermission(1, 1, adminAuth()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("защищены");
        }
    }

    // ----------------------------------------------------------------
    // validatePermissionManagerAccess
    // ----------------------------------------------------------------

    @Nested @DisplayName("PERMISSION_MANAGER — доступ к ролям")
    class PermissionManagerAccess {

        @Test
        @DisplayName("ADMIN может управлять любой ролью")
        void adminManagesAnyRole() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity perm = makePermission(1, "rf-contract-svc", "C", "a");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));
            when(rolePermissionRepository.existsById(any())).thenReturn(false);
            when(rolePermissionRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() ->
                    permissionService.assignPermission(10, 1, adminAuth()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("PERMISSION_MANAGER управляет только своими ролями")
        void pmManagesOwnRole() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity perm = makePermission(1, "rf-contract-svc", "C", "a");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));
            when(rolePermissionRepository.existsById(any())).thenReturn(false);
            when(rolePermissionRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() ->
                    permissionService.assignPermission(10, 1, pmAuth("user1")))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("PERMISSION_MANAGER не может управлять системной ролью")
        void pmCannotManageSystemRole() {
            RoleEntity role = makeRole(5, "USER", "system");
            when(roleRepository.findById(5L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() ->
                    permissionService.assignPermission(5, 1, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("создали сами");
        }

        @Test
        @DisplayName("PERMISSION_MANAGER не может управлять чужой ролью")
        void pmCannotManageForeignRole() {
            RoleEntity role = makeRole(10, "ANALYST", "otheruser");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() ->
                    permissionService.assignPermission(10, 1, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("создали сами");
        }

        @Test
        @DisplayName("Пользователь без нужной роли получает AccessDeniedException")
        void regularUserGetsDenied() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() ->
                    permissionService.assignPermission(10, 1, managerAuth()))
                    .isInstanceOf(AccessDeniedException.class);
        }
    }

    // ----------------------------------------------------------------
    // validatePermissionNotRestricted
    // ----------------------------------------------------------------

    @Nested @DisplayName("Ограничение прав rf-auth-svc для PERMISSION_MANAGER")
    class AuthServicePermissionGuard {

        @Test
        @DisplayName("PERMISSION_MANAGER не может назначать права rf-auth-svc")
        void pmCannotAssignAuthServicePermission() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity authPerm = makePermission(1, "rf-auth-svc",
                    "AdminUserController", "deleteUser");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(authPerm));

            assertThatThrownBy(() ->
                    permissionService.assignPermission(10, 1, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("rf-auth-svc");
        }

        @Test
        @DisplayName("ADMIN может назначать права rf-auth-svc")
        void adminCanAssignAuthServicePermission() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity authPerm = makePermission(1, "rf-auth-svc",
                    "AdminUserController", "deleteUser");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(authPerm));
            when(rolePermissionRepository.existsById(any())).thenReturn(false);
            when(rolePermissionRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() ->
                    permissionService.assignPermission(10, 1, adminAuth()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("PERMISSION_MANAGER может назначать права других сервисов")
        void pmCanAssignBusinessServicePermissions() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity perm = makePermission(1, "rf-contract-svc",
                    "ContractController", "createContract");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));
            when(rolePermissionRepository.existsById(any())).thenReturn(false);
            when(rolePermissionRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() ->
                    permissionService.assignPermission(10, 1, pmAuth("user1")))
                    .doesNotThrowAnyException();
        }
    }

    // ----------------------------------------------------------------
    // isProtectedRole
    // ----------------------------------------------------------------

    @Nested @DisplayName("isProtectedRole")
    class IsProtectedRole {

        @Test
        @DisplayName("ADMIN является защищённой ролью")
        void adminIsProtected() {
            assertThat(permissionService.isProtectedRole("ADMIN")).isTrue();
        }

        @Test
        @DisplayName("Кастомные роли не являются защищёнными")
        void customRoleIsNotProtected() {
            assertThat(permissionService.isProtectedRole("ANALYST")).isFalse();
            assertThat(permissionService.isProtectedRole("MANAGER")).isFalse();
        }
    }

    // ----------------------------------------------------------------
    // Kafka — ошибка публикации не прерывает транзакцию
    // ----------------------------------------------------------------

    @Nested @DisplayName("Kafka — отказоустойчивость")
    class KafkaResilience {

        @Test
        @DisplayName("Ошибка Kafka не прерывает операцию назначения права")
        void kafkaFailureDoesNotBreakAssign() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity perm = makePermission(1, "rf-contract-svc", "C", "a");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));
            when(rolePermissionRepository.existsById(any())).thenReturn(false);
            when(rolePermissionRepository.save(any())).thenAnswer(i -> i.getArgument(0));
            when(kafkaTemplate.send(any(), any()))
                    .thenThrow(new RuntimeException("Kafka unavailable"));

            // Операция должна завершиться успешно несмотря на ошибку Kafka
            assertThatCode(() ->
                    permissionService.assignPermission(10, 1, adminAuth()))
                    .doesNotThrowAnyException();

            verify(rolePermissionRepository).save(any());
        }
    }

    // ----------------------------------------------------------------
    // deletePermission
    // ----------------------------------------------------------------

    @Nested @DisplayName("deletePermission")
    class DeletePermission {

        @Test
        @DisplayName("Удаляет право и инвалидирует кэш для затронутых ролей")
        void deletesPermissionAndPublishesEvent() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            PermissionEntity perm = makePermission(1, "rf-contract-svc", "C", "a");
            perm.getRoles().add(role);
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));

            permissionService.deletePermission(1);

            verify(permissionRepository).delete(perm);
            // Kafka должен быть вызван для инвалидации кэша затронутых ролей
            verify(kafkaTemplate).send(eq("rf.permissions.invalidated"), any());
        }

        @Test
        @DisplayName("Не публикует Kafka-событие если право не было назначено ни одной роли")
        void noKafkaEventWhenNoRolesAffected() {
            PermissionEntity perm = makePermission(1, "rf-contract-svc", "C", "a");
            // roles пустой
            when(permissionRepository.findById(1)).thenReturn(Optional.of(perm));

            permissionService.deletePermission(1);

            verify(permissionRepository).delete(perm);
            verify(kafkaTemplate, never()).send(any(), any());
        }
    }
}
