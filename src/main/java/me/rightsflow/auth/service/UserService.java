package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.RoleDto;
import me.rightsflow.auth.dto.UserDto;
import me.rightsflow.auth.dto.UserRequestDto;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.RoleRepository;
import me.rightsflow.auth.repository.UserRepository;
import org.springframework.data.domain.Sort;
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
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));
    }

    @Transactional
    public UserDto createUser(UserRequestDto request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + request.getUsername());
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already exists: " + request.getEmail());
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
        user.setUserType("USER"); // Тип по умолчанию

        Set<RoleEntity> roles = findRolesByNames(request.getRoles());
        user.setRoles(roles);

        UserEntity savedUser = userRepository.save(user);
        log.info("Created new user: {}", savedUser.getUsername());
        return toUserDto(savedUser);
    }

    @Transactional
    public UserDto updateUser(Integer id, UserRequestDto request) {
        UserEntity user = userRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        // Обновляем поля
        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        user.setEnabled(request.getEnabled());
        user.setAccountNonExpired(request.getAccountNonExpired());
        user.setAccountNonLocked(request.getAccountNonLocked());
        user.setExpirationDate(request.getExpirationDate());

        // Обновляем пароль, только если он предоставлен
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
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        // Не позволяем удалять сервисных пользователей через этот интерфейс
        if (!"USER".equals(user.getUserType())) {
            throw new IllegalArgumentException("Cannot delete non-standard user type: " + user.getUserType());
        }

        userRepository.delete(user);
        log.info("Deleted user: {}", user.getUsername());
    }

    // --- Role Management ---

    @Transactional(readOnly = true)
    public List<RoleDto> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(this::toRoleDto)
                .collect(Collectors.toList());
    }

    @Transactional
    public RoleDto createRole(RoleDto request) {
        if (roleRepository.existsByName(request.getName())) {
            throw new IllegalArgumentException("Role already exists: " + request.getName());
        }
        RoleEntity role = new RoleEntity();
        role.setName(request.getName().toUpperCase());
        role.setDescription(request.getDescription());
        RoleEntity savedRole = roleRepository.save(role);
        log.info("Created new role: {}", savedRole.getName());
        return toRoleDto(savedRole);
    }

    @Transactional
    public void deleteRole(Integer id) {
        RoleEntity role = roleRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException("Role not found with id: " + id));

        // Проверяем, используется ли роль
        if (!role.getUsers().isEmpty()) {
            throw new IllegalArgumentException("Cannot delete role '" + role.getName() + "' as it is assigned to users.");
        }

        roleRepository.delete(role);
        log.info("Deleted role: {}", role.getName());
    }

    // --- Helper Methods ---

    private Set<RoleEntity> findRolesByNames(Set<String> roleNames) {
        return roleNames.stream()
                .map(roleName -> roleRepository.findByName(roleName)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleName)))
                .collect(Collectors.toSet());
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
        dto.setRoles(user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()));
        return dto;
    }

    private RoleDto toRoleDto(RoleEntity role) {
        RoleDto dto = new RoleDto();
        dto.setId(role.getId());
        dto.setName(role.getName());
        dto.setDescription(role.getDescription());
        return dto;
    }
}
