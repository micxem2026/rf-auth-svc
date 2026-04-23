package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.RoleDto;
import me.rightsflow.auth.dto.UserSummaryDto;
import me.rightsflow.auth.dto.UserDto;
import me.rightsflow.auth.dto.UserRequestDto;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.RoleRepository;
import me.rightsflow.auth.repository.UserRepository;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Пользователи, которых нельзя удалить или отключить через UI.
     * Защищает от случайной потери доступа к системе.
     */
    private static final Set<String> PROTECTED_USERNAMES = Set.of("admin");

    /**
     * Системные роли — нельзя удалять и изменять.
     */
    private static final Set<String> SYSTEM_ROLES = Set.of("ADMIN", "SERVICE", "PERMISSION_MANAGER");

    // ================================================================
    // Users
    // ================================================================

    @Transactional(readOnly = true)
    public List<UserDto> getAllUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.ASC, "username")).stream()
                .map(this::toUserDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public UserDto getUserById(Integer id) {
        return userRepository.findById(id.longValue())
                .map(this::toUserDto)
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + id));
    }

    @Transactional
    public UserDto createUser(UserRequestDto request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException(
                    "Username already exists: " + request.getUsername());
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException(
                    "Email already exists: " + request.getEmail());
        }
        if (!StringUtils.hasText(request.getPassword())) {
            throw new IllegalArgumentException("Password is required for new user");
        }

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(request.getEnabled());
        user.setAccountNonExpired(request.getAccountNonExpired());
        user.setAccountNonLocked(request.getAccountNonLocked());
        user.setExpirationDate(request.getExpirationDate());
        user.setUserType("USER");

        Set<RoleEntity> roles = findRolesByNames(request.getRoles());
        user.setRoles(roles);

        UserEntity savedUser = userRepository.save(user);
        log.info("Created new user: {}", savedUser.getUsername());
        return toUserDto(savedUser);
    }

    @Transactional
    public UserDto updateUser(Integer id, UserRequestDto request) {
        UserEntity user = userRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + id));

        // Защищённого пользователя нельзя отключить или заблокировать
        if (PROTECTED_USERNAMES.contains(user.getUsername())) {
            if (Boolean.FALSE.equals(request.getEnabled())) {
                throw new IllegalArgumentException(
                        "Нельзя отключить системного пользователя '" +
                        user.getUsername() + "'.");
            }
            if (Boolean.FALSE.equals(request.getAccountNonLocked())) {
                throw new IllegalArgumentException(
                        "Нельзя заблокировать системного пользователя '" +
                        user.getUsername() + "'.");
            }
        }

        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        user.setEnabled(request.getEnabled());
        user.setAccountNonExpired(request.getAccountNonExpired());
        user.setAccountNonLocked(request.getAccountNonLocked());
        user.setExpirationDate(request.getExpirationDate());

        if (StringUtils.hasText(request.getPassword())) {
            user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        }

        Set<RoleEntity> roles = findRolesByNames(request.getRoles());
        user.setRoles(roles);

        UserEntity updatedUser = userRepository.save(user);
        log.info("Updated user: {}", updatedUser.getUsername());
        return toUserDto(updatedUser);
    }

    @Transactional
    public void deleteUser(Integer id) {
        UserEntity user = userRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + id));

        // Системных пользователей удалять нельзя
        if (PROTECTED_USERNAMES.contains(user.getUsername())) {
            throw new IllegalArgumentException(
                    "Нельзя удалить системного пользователя '" +
                    user.getUsername() + "'.");
        }

        // Сервисных пользователей удаляют только через удаление OAuth2-клиента
        if (!"USER".equals(user.getUserType())) {
            throw new IllegalArgumentException(
                    "Cannot delete non-standard user type: " + user.getUserType());
        }

        userRepository.delete(user);
        log.info("Deleted user: {}", user.getUsername());
    }

    /**
     * Возвращает true если пользователь является системным (защищён от удаления).
     * Используется в UI для скрытия кнопки удаления.
     */
    public boolean isProtectedUser(String username) {
        return PROTECTED_USERNAMES.contains(username);
    }

    // ================================================================
    // Roles
    // ================================================================

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(this::toRoleDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public RoleDto getRoleById(Integer id) {
        return roleRepository.findById(id.longValue())
                .map(this::toRoleDto)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found with id: " + id));
    }

    @Transactional
    public RoleDto createRole(RoleDto request) {
        if (roleRepository.existsByName(request.getName())) {
            throw new IllegalArgumentException(
                    "Role already exists: " + request.getName());
        }
        RoleEntity role = new RoleEntity();
        role.setName(request.getName().toUpperCase());
        role.setDescription(request.getDescription());
        role.setCreatedBy(request.getCreatedBy() != null ? request.getCreatedBy() : "system");
        RoleEntity savedRole = roleRepository.save(role);
        log.info("Created new role: {}", savedRole.getName());
        return toRoleDto(savedRole);
    }

    @Transactional
    public void deleteRole(Integer id, Authentication authentication) {
        RoleEntity role = roleRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found with id: " + id));

        if (SYSTEM_ROLES.contains(role.getName())) {
            throw new IllegalArgumentException(
                    "Нельзя удалить системную роль '" + role.getName() + "'.");
        }

        // PERMISSION_MANAGER может удалять только свои роли
        if (authentication != null) {
            boolean isAdmin = authentication.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
            if (!isAdmin) {
                if (!authentication.getName().equals(role.getCreatedBy())) {
                    throw new IllegalArgumentException(
                            "Вы можете удалять только роли, которые создали сами.");
                }
            }
        }

        if (!role.getUsers().isEmpty()) {
            throw new IllegalArgumentException(
                    "Cannot delete role '" + role.getName() +
                    "' as it is assigned to users.");
        }

        roleRepository.delete(role);
        log.info("Deleted role: {}", role.getName());
    }

    // ================================================================
    // Role assignment for PERMISSION_MANAGER
    // ================================================================

    /**
     * Облегчённый список пользователей для вкладки назначения ролей.
     * Возвращает только id, username, displayName, userType и roles —
     * без email и служебных полей.
     */
    @Transactional(readOnly = true)
    public List<UserSummaryDto> getAllUsersSummary() {
        return userRepository.findAll(Sort.by(Sort.Direction.ASC, "username"))
                .stream()
                //.filter(u -> "USER".equals(u.getUserType()))
                .map(this::toUserSummaryDto)
                .collect(Collectors.toList());
    }

    /**
     * Назначает роль пользователю.
     * ADMIN — любую роль.
     * PERMISSION_MANAGER — только роли которые он сам создал.
     */
    @Transactional
    public UserDto assignRoleToUser(Integer userId, Integer roleId,
                                     Authentication authentication) {
        UserEntity user = userRepository.findById(userId.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + userId));

        RoleEntity role = roleRepository.findById(roleId.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found with id: " + roleId));

        validateRoleAssignmentAllowed(role, authentication);

        if (user.getRoles().stream().anyMatch(r -> r.getId().equals(roleId))) {
            throw new IllegalArgumentException(
                    "Роль '" + role.getName() +
                    "' уже назначена пользователю '" + user.getUsername() + "'.");
        }

        user.getRoles().add(role);
        userRepository.save(user);
        log.info("Role '{}' assigned to user '{}' by '{}'",
                role.getName(), user.getUsername(), authentication.getName());
        return toUserDto(user);
    }

    /**
     * Снимает роль с пользователя.
     * ADMIN — любую роль.
     * PERMISSION_MANAGER — только роли которые он сам создал.
     */
    @Transactional
    public UserDto revokeRoleFromUser(Integer userId, Integer roleId,
                                       Authentication authentication) {
        UserEntity user = userRepository.findById(userId.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with id: " + userId));

        RoleEntity role = roleRepository.findById(roleId.longValue())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Role not found with id: " + roleId));

        validateRoleAssignmentAllowed(role, authentication);

        boolean removed = user.getRoles().removeIf(r -> r.getId().equals(roleId));
        if (!removed) {
            throw new IllegalArgumentException(
                    "Роль '" + role.getName() +
                    "' не назначена пользователю '" + user.getUsername() + "'.");
        }

        userRepository.save(user);
        log.info("Role '{}' revoked from user '{}' by '{}'",
                role.getName(), user.getUsername(), authentication.getName());
        return toUserDto(user);
    }

    /**
     * Проверяет что текущий пользователь имеет право назначать/снимать роль.
     * ADMIN — любую роль.
     * PERMISSION_MANAGER — только роли которые сам создал.
     */
    private void validateRoleAssignmentAllowed(RoleEntity role,
                                                Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (isAdmin) return;

        if ("system".equals(role.getCreatedBy()) ||
                !authentication.getName().equals(role.getCreatedBy())) {
            throw new IllegalArgumentException(
                    "Вы можете назначать только роли, которые создали сами. " +
                    "Роль '" + role.getName() + "' вам недоступна.");
        }
    }

    // ================================================================
    // Helpers
    // ================================================================

    private Set<RoleEntity> findRolesByNames(Set<String> roleNames) {
        return roleNames.stream()
                .map(roleName -> roleRepository.findByName(roleName)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Role not found: " + roleName)))
                .collect(Collectors.toSet());
    }

    private UserSummaryDto toUserSummaryDto(UserEntity user) {
        UserSummaryDto dto = new UserSummaryDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setDisplayName(user.getDisplayName());
        dto.setUserType(user.getUserType());
        dto.setRoles(user.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toSet()));
        return dto;
    }

    private UserDto toUserDto(UserEntity user) {
        UserDto dto = new UserDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setDisplayName(user.getDisplayName());
        dto.setEmail(user.getEmail());
        dto.setEnabled(user.getEnabled());
        dto.setAccountNonExpired(user.getAccountNonExpired());
        dto.setAccountNonLocked(user.getAccountNonLocked());
        dto.setExpirationDate(user.getExpirationDate());
        dto.setLastLogon(user.getLastLogon());
        dto.setUserType(user.getUserType());
        dto.setRoles(user.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toSet()));
        dto.setProtectedUser(PROTECTED_USERNAMES.contains(user.getUsername()));
        return dto;
    }

    private RoleDto toRoleDto(RoleEntity role) {
        RoleDto dto = new RoleDto();
        dto.setId(role.getId());
        dto.setName(role.getName());
        dto.setDescription(role.getDescription());
        dto.setCreatedBy(role.getCreatedBy());
        return dto;
    }
}
