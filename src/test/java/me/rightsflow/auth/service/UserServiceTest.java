package me.rightsflow.auth.service;

import me.rightsflow.auth.dto.RoleDto;
import me.rightsflow.auth.dto.UserDto;
import me.rightsflow.auth.dto.UserRequestDto;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.RoleRepository;
import me.rightsflow.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService")
class UserServiceTest {

    @Mock UserRepository userRepository;
    @Mock RoleRepository roleRepository;
    @Mock PasswordEncoder passwordEncoder;

    @InjectMocks UserService userService;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private UserEntity makeUser(Integer id, String username, String userType) {
        UserEntity u = new UserEntity();
        u.setId(id);
        u.setUsername(username);
        u.setDisplayName(username);
        u.setEmail(username + "@test.com");
        u.setPasswordHash("hash");
        u.setEnabled(true);
        u.setAccountNonExpired(true);
        u.setAccountNonLocked(true);
        u.setUserType(userType);
        u.setRoles(new HashSet<>());
        return u;
    }

    private RoleEntity makeRole(Integer id, String name, String createdBy) {
        RoleEntity r = new RoleEntity();
        r.setId(id);
        r.setName(name);
        r.setCreatedBy(createdBy);
        r.setUsers(new HashSet<>());
        return r;
    }

    private Authentication adminAuth() {
        return new UsernamePasswordAuthenticationToken("admin", null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private Authentication pmAuth(String username) {
        return new UsernamePasswordAuthenticationToken(username, null,
                List.of(new SimpleGrantedAuthority("ROLE_PERMISSION_MANAGER")));
    }

    // ----------------------------------------------------------------
    // deleteUser
    // ----------------------------------------------------------------

    @Nested @DisplayName("deleteUser")
    class DeleteUser {

        @Test
        @DisplayName("Удаляет обычного пользователя")
        void deletesRegularUser() {
            UserEntity user = makeUser(2, "john", "USER");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));

            userService.deleteUser(2);

            verify(userRepository).delete(user);
        }

        @Test
        @DisplayName("Запрещает удалять системного пользователя admin")
        void preventsDeleteAdmin() {
            UserEntity admin = makeUser(1, "admin", "USER");
            when(userRepository.findById(1L)).thenReturn(Optional.of(admin));

            assertThatThrownBy(() -> userService.deleteUser(1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("admin");
        }

        @Test
        @DisplayName("Запрещает удалять SERVICE-пользователей")
        void preventsDeleteServiceUser() {
            UserEntity svc = makeUser(3, "my-service", "SERVICE");
            when(userRepository.findById(3L)).thenReturn(Optional.of(svc));

            assertThatThrownBy(() -> userService.deleteUser(3))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Бросает исключение если пользователь не найден")
        void throwsWhenNotFound() {
            when(userRepository.findById(99L)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.deleteUser(99))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }

    // ----------------------------------------------------------------
    // updateUser — защита системного пользователя
    // ----------------------------------------------------------------

    @Nested @DisplayName("updateUser — защита admin")
    class UpdateUserProtection {

        private UserRequestDto makeRequest(boolean enabled, boolean locked) {
            UserRequestDto r = new UserRequestDto();
            r.setDisplayName("Admin");
            r.setEmail("admin@test.com");
            r.setEnabled(enabled);
            r.setAccountNonLocked(locked);
            r.setAccountNonExpired(true);
            r.setRoles(Set.of("ADMIN"));
            return r;
        }

        @Test
        @DisplayName("Запрещает отключать системного пользователя")
        void preventsDisablingAdmin() {
            UserEntity admin = makeUser(1, "admin", "USER");
            when(userRepository.findById(1L)).thenReturn(Optional.of(admin));

            assertThatThrownBy(() -> userService.updateUser(1, makeRequest(false, true)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("отключить");
        }

        @Test
        @DisplayName("Запрещает блокировать системного пользователя")
        void preventsLockingAdmin() {
            UserEntity admin = makeUser(1, "admin", "USER");
            when(userRepository.findById(1L)).thenReturn(Optional.of(admin));

            assertThatThrownBy(() -> userService.updateUser(1, makeRequest(true, false)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("заблокировать");
        }

        @Test
        @DisplayName("Разрешает другие обновления admin")
        void allowsOtherUpdatesForAdmin() {
            UserEntity admin = makeUser(1, "admin", "USER");
            RoleEntity adminRole = makeRole(1, "ADMIN", "system");
            when(userRepository.findById(1L)).thenReturn(Optional.of(admin));
            when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
            when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            UserRequestDto req = makeRequest(true, true);
            req.setDisplayName("Super Admin");

            assertThatCode(() -> userService.updateUser(1, req))
                    .doesNotThrowAnyException();
        }
    }

    // ----------------------------------------------------------------
    // deleteRole
    // ----------------------------------------------------------------

    @Nested @DisplayName("deleteRole")
    class DeleteRole {

        @Test
        @DisplayName("ADMIN может удалить обычную роль")
        void adminCanDeleteRole() {
            RoleEntity role = makeRole(10, "ANALYST", "admin");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            userService.deleteRole(10, adminAuth());

            verify(roleRepository).delete(role);
        }

        @Test
        @DisplayName("Запрещает удалять системную роль ADMIN")
        void preventsDeleteSystemRole() {
            RoleEntity role = makeRole(1, "ADMIN", "system");
            when(roleRepository.findById(1L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.deleteRole(1, adminAuth()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("системную");
        }

        @Test
        @DisplayName("PERMISSION_MANAGER может удалить созданную им роль")
        void pmCanDeleteOwnRole() {
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            userService.deleteRole(10, pmAuth("user1"));

            verify(roleRepository).delete(role);
        }

        @Test
        @DisplayName("PERMISSION_MANAGER не может удалить чужую роль")
        void pmCannotDeleteForeignRole() {
            RoleEntity role = makeRole(10, "ANALYST", "otheruser");
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.deleteRole(10, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("создали сами");
        }

        @Test
        @DisplayName("Запрещает удалять роль назначенную пользователям")
        void preventsDeleteAssignedRole() {
            RoleEntity role = makeRole(10, "ANALYST", "admin");
            role.getUsers().add(makeUser(2, "john", "USER"));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.deleteRole(10, adminAuth()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("assigned to users");
        }
    }

    // ----------------------------------------------------------------
    // assignRoleToUser / revokeRoleFromUser
    // ----------------------------------------------------------------

    @Nested @DisplayName("assignRoleToUser")
    class AssignRole {

        @Test
        @DisplayName("ADMIN назначает любую роль")
        void adminAssignsAnyRole() {
            UserEntity user = makeUser(2, "john", "USER");
            RoleEntity role = makeRole(10, "ANALYST", "system");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() -> userService.assignRoleToUser(2, 10, adminAuth()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("PERMISSION_MANAGER назначает только свою роль")
        void pmAssignsOwnRole() {
            UserEntity user = makeUser(2, "john", "USER");
            RoleEntity role = makeRole(10, "ANALYST", "user1");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() -> userService.assignRoleToUser(2, 10, pmAuth("user1")))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("PERMISSION_MANAGER не может назначить системную роль")
        void pmCannotAssignSystemRole() {
            UserEntity user = makeUser(2, "john", "USER");
            RoleEntity role = makeRole(1, "ADMIN", "system");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(1L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.assignRoleToUser(2, 1, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("создали сами");
        }

        @Test
        @DisplayName("PERMISSION_MANAGER не может назначить чужую роль")
        void pmCannotAssignForeignRole() {
            UserEntity user = makeUser(2, "john", "USER");
            RoleEntity role = makeRole(10, "ANALYST", "otheruser");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.assignRoleToUser(2, 10, pmAuth("user1")))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Запрещает назначать уже назначенную роль")
        void preventsDoubleAssignment() {
            RoleEntity role = makeRole(10, "ANALYST", "admin");
            UserEntity user = makeUser(2, "john", "USER");
            user.getRoles().add(role);
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.assignRoleToUser(2, 10, adminAuth()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("уже назначена");
        }
    }

    @Nested @DisplayName("revokeRoleFromUser")
    class RevokeRole {

        @Test
        @DisplayName("ADMIN снимает любую роль")
        void adminRevokesAnyRole() {
            RoleEntity role = makeRole(10, "ANALYST", "system");
            UserEntity user = makeUser(2, "john", "USER");
            user.getRoles().add(role);
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));
            when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));

            assertThatCode(() -> userService.revokeRoleFromUser(2, 10, adminAuth()))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Бросает исключение если роль не была назначена")
        void throwsWhenRoleNotAssigned() {
            RoleEntity role = makeRole(10, "ANALYST", "admin");
            UserEntity user = makeUser(2, "john", "USER");
            when(userRepository.findById(2L)).thenReturn(Optional.of(user));
            when(roleRepository.findById(10L)).thenReturn(Optional.of(role));

            assertThatThrownBy(() -> userService.revokeRoleFromUser(2, 10, adminAuth()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("не назначена");
        }
    }
}
