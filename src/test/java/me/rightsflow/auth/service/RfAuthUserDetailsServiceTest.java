package me.rightsflow.auth.service;

import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RfAuthUserDetailsService")
class RfAuthUserDetailsServiceTest {

    @Mock UserRepository userRepository;

    @InjectMocks RfAuthUserDetailsService userDetailsService;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private UserEntity makeUser(String username, boolean enabled,
                                 boolean nonLocked, boolean nonExpired,
                                 LocalDateTime expirationDate,
                                 Set<RoleEntity> roles) {
        UserEntity u = new UserEntity();
        u.setId(1);
        u.setUsername(username);
        u.setDisplayName(username);
        u.setEmail(username + "@test.com");
        u.setPasswordHash("hash");
        u.setEnabled(enabled);
        u.setAccountNonLocked(nonLocked);
        u.setAccountNonExpired(nonExpired);
        u.setExpirationDate(expirationDate);
        u.setUserType("USER");
        u.setRoles(roles);
        return u;
    }

    private RoleEntity makeRole(String name) {
        RoleEntity r = new RoleEntity();
        r.setId(1);
        r.setName(name);
        r.setCreatedBy("system");
        r.setUsers(new HashSet<>());
        return r;
    }

    // ================================================================
    // loadUserByUsername
    // ================================================================

    @Nested @DisplayName("loadUserByUsername")
    class LoadUser {

        @Test
        @DisplayName("Загружает существующего пользователя с ролями")
        void loadsUserWithRoles() {
            Set<RoleEntity> roles = Set.of(makeRole("ADMIN"), makeRole("USER"));
            UserEntity user = makeUser("admin", true, true, true, null, roles);
            when(userRepository.findByUsernameWithRoles("admin"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("admin");

            assertThat(details.getUsername()).isEqualTo("admin");
            assertThat(details.getAuthorities())
                    .extracting("authority")
                    .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");
        }

        @Test
        @DisplayName("Бросает UsernameNotFoundException для несуществующего пользователя")
        void throwsForUnknownUser() {
            when(userRepository.findByUsernameWithRoles("unknown"))
                    .thenReturn(Optional.empty());

            assertThatThrownBy(() -> userDetailsService.loadUserByUsername("unknown"))
                    .isInstanceOf(UsernameNotFoundException.class);
        }

        @Test
        @DisplayName("isEnabled возвращает false для отключённого пользователя")
        void disabledUserIsNotEnabled() {
            UserEntity user = makeUser("disabled", false, true, true, null, Set.of());
            when(userRepository.findByUsernameWithRoles("disabled"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("disabled");

            assertThat(details.isEnabled()).isFalse();
        }

        @Test
        @DisplayName("isAccountNonExpired возвращает false если дата истечения прошла")
        void expiredUserIsNotNonExpired() {
            UserEntity user = makeUser("expired", true, true, true,
                    LocalDateTime.now().minusDays(1), Set.of());
            when(userRepository.findByUsernameWithRoles("expired"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("expired");

            assertThat(details.isAccountNonExpired()).isFalse();
        }

        @Test
        @DisplayName("isAccountNonExpired возвращает true если дата истечения в будущем")
        void activeExpirationUserIsNonExpired() {
            UserEntity user = makeUser("active", true, true, true,
                    LocalDateTime.now().plusDays(30), Set.of());
            when(userRepository.findByUsernameWithRoles("active"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("active");

            assertThat(details.isAccountNonExpired()).isTrue();
        }

        @Test
        @DisplayName("isAccountNonExpired возвращает true если дата истечения не задана")
        void noExpirationUserIsNonExpired() {
            UserEntity user = makeUser("noexp", true, true, true, null, Set.of());
            when(userRepository.findByUsernameWithRoles("noexp"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("noexp");

            assertThat(details.isAccountNonExpired()).isTrue();
        }

        @Test
        @DisplayName("isAccountNonLocked возвращает false для заблокированного")
        void lockedUserIsNotNonLocked() {
            UserEntity user = makeUser("locked", true, false, true, null, Set.of());
            when(userRepository.findByUsernameWithRoles("locked"))
                    .thenReturn(Optional.of(user));

            UserDetails details = userDetailsService.loadUserByUsername("locked");

            assertThat(details.isAccountNonLocked()).isFalse();
        }
    }

    // ================================================================
    // RfAuthUserPrincipal
    // ================================================================

    @Nested @DisplayName("RfAuthUserPrincipal")
    class PrincipalFields {

        @Test
        @DisplayName("Возвращает корректные дополнительные поля")
        void returnsCorrectAdditionalFields() {
            UserEntity user = makeUser("john", true, true, true, null, Set.of());
            user.setId(42);
            user.setDisplayName("John Doe");
            user.setEmail("john@test.com");
            user.setUserType("USER");
            when(userRepository.findByUsernameWithRoles("john"))
                    .thenReturn(Optional.of(user));

            RfAuthUserDetailsService.RfAuthUserPrincipal principal =
                    (RfAuthUserDetailsService.RfAuthUserPrincipal)
                    userDetailsService.loadUserByUsername("john");

            assertThat(principal.getUserId()).isEqualTo(42L);
            assertThat(principal.getDisplayName()).isEqualTo("John Doe");
            assertThat(principal.getEmail()).isEqualTo("john@test.com");
            assertThat(principal.getUserType()).isEqualTo("USER");
        }
    }
}
