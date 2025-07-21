package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class RfAuthUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Загружает данные пользователя по его имени пользователя (username).
     *
     * @param username Имя пользователя.
     * @return Объект UserDetails, содержащий информацию о пользователе и его ролях.
     * @throws UsernameNotFoundException Если пользователь не найден.
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        UserEntity user = userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() -> {
                    log.warn("User not found: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });

        log.debug("User found: {}, roles: {}", user.getUsername(),
                user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toList()));

        return new RfAuthUserPrincipal(user);
    }

    public static class RfAuthUserPrincipal implements UserDetails {

        private final UserEntity user;

        public RfAuthUserPrincipal(UserEntity user) {
            this.user = user;
        }

        public Long getUserId() {
            return user.getId().longValue();
        }

        public String getDisplayName() {
            return user.getDisplayName();
        }

        public String getEmail() {
            return user.getEmail();
        }

        public String getUserType() {
            return user.getUserType();
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName().toUpperCase()))
                    .collect(Collectors.toList());
        }

        @Override
        public String getPassword() {
            return user.getPasswordHash();
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return user.getAccountNonExpired() &&
                    (user.getExpirationDate() == null || user.getExpirationDate().isAfter(LocalDateTime.now()));
        }

        @Override
        public boolean isAccountNonLocked() {
            return user.getAccountNonLocked();
        }

        @Override
        public boolean isEnabled() {
            return user.getEnabled();
        }

    }
}
