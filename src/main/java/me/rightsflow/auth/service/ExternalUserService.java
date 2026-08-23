package me.rightsflow.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.*;
import me.rightsflow.auth.entity.RoleEntity;
import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.RoleRepository;
import me.rightsflow.auth.repository.UserRepository;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Сервис внешнего API для admin_client: управление SERVICE-пользователями,
 * которых создал сам вызывающий admin_client.
 * <p>
 * Правило доступа: ADMIN — любые пользователи; ADMIN_CLIENT — только те,
 * у кого users.created_by == текущий username.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ExternalUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ClientRegistrationService clientRegistrationService;

    /**
     * Системные/административные роли — admin_client не может их
     * назначать/снимать (защита от эскалации привилегий). Обычные бизнес-роли,
     * включая SERVICE, admin_client назначать может.
     */
    private static final Set<String> PROTECTED_ROLES_FOR_ADMIN_CLIENT =
            Set.of("ADMIN", "PERMISSION_MANAGER", "ADMIN_CLIENT", "SERVICE");

    @Transactional
    public ExternalServiceUserResponse createServiceUser(ExternalCreateServiceUserRequest request,
                                                         Authentication authentication) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists: " + request.getUsername());
        }

        // Резолвим и валидируем роли ДО создания клиента — чтобы не создавать
        // "хвост" из клиента/пользователя при недопустимой роли.
        Set<RoleEntity> roles = resolveRoles(request.getRoles());
        validateRolesAssignable(roles, authentication);

        ClientRegistrationResponse clientResponse = clientRegistrationService.registerServiceClient(request, authentication);

        UserEntity user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new IllegalStateException(
                        "Service user was not created for username: " + request.getUsername()));
        user.getRoles().addAll(roles);
        UserEntity saved = userRepository.save(user);

        log.info("External API: service user '{}' created by '{}' with roles {}",
                saved.getUsername(), authentication.getName(), request.getRoles());

        return toServiceUserResponse(saved, clientResponse);
    }

    @Transactional
    public void deleteUser(Integer id, Authentication authentication) {
        UserEntity user = getOwnedUser(id, authentication);
        clientRegistrationService.deleteClientAndServiceUser(user.getUsername());
        log.info("External API: user '{}' deleted by '{}'", user.getUsername(), authentication.getName());
    }

    @Transactional
    public ExternalUserDto updateUser(Integer id, ExternalUpdateUserRequest request, Authentication authentication) {
        UserEntity user = getOwnedUser(id, authentication);

        user.setDisplayName(request.getDisplayName());
        user.setEmail(request.getEmail());
        user.setEnabled(request.getEnabled());
        user.setAccountNonExpired(request.getAccountNonExpired());
        user.setAccountNonLocked(request.getAccountNonLocked());
        user.setExpirationDate(request.getExpirationDate());

        UserEntity updated = userRepository.save(user);
        log.info("External API: user '{}' updated by '{}'", updated.getUsername(), authentication.getName());
        return toDto(updated);
    }

    @Transactional
    public void changePassword(Integer id, ExternalChangePasswordRequest request, Authentication authentication) {
        UserEntity user = getOwnedUser(id, authentication);
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        if ("SERVICE".equals(user.getUserType())) {
            clientRegistrationService.rotateServiceClientSecret(user.getUsername(), request.getNewPassword());
        }

        log.info("External API: password changed for '{}' by '{}'", user.getUsername(), authentication.getName());
    }

    @Transactional
    public ExternalUserDto assignRoles(Integer id, ExternalRoleNamesRequest request, Authentication authentication) {
        UserEntity user = getOwnedUser(id, authentication);
        Set<RoleEntity> roles = resolveRoles(request.getRoles());
        validateRolesAssignable(roles, authentication);
        user.getRoles().addAll(roles);
        UserEntity updated = userRepository.save(user);
        log.info("External API: roles {} assigned to '{}' by '{}'",
                request.getRoles(), user.getUsername(), authentication.getName());
        return toDto(updated);
    }

    @Transactional
    public ExternalUserDto revokeRoles(Integer id, ExternalRoleNamesRequest request, Authentication authentication) {
        UserEntity user = getOwnedUser(id, authentication);
        Set<RoleEntity> roles = resolveRoles(request.getRoles());
        user.getRoles().removeAll(roles);
        UserEntity updated = userRepository.save(user);
        log.info("External API: roles {} revoked from '{}' by '{}'",
                request.getRoles(), user.getUsername(), authentication.getName());
        return toDto(updated);
    }

    @Transactional(readOnly = true)
    public ExternalUserDto getUser(Integer id, Authentication authentication) {
        return toDto(getOwnedUser(id, authentication));
    }

    @Transactional(readOnly = true)
    public List<ExternalUserDto> getUsers(Authentication authentication) {
        List<UserEntity> users = isAdmin(authentication)
                ? userRepository.findAll(Sort.by(Sort.Direction.ASC, "username"))
                : userRepository.findAllByCreatedByOrderByUsername(authentication.getName());
        return users.stream().map(this::toDto).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<RoleDto> getAssignableRoles(Authentication authentication) {
        boolean admin = isAdmin(authentication);
        return roleRepository.findAll(Sort.by(Sort.Direction.ASC, "name")).stream()
                .filter(role -> admin || !PROTECTED_ROLES_FOR_ADMIN_CLIENT.contains(role.getName()))
                .map(this::toRoleDto)
                .collect(Collectors.toList());
    }

    // ---------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------

    private UserEntity getOwnedUser(Integer id, Authentication authentication) {
        UserEntity user = userRepository.findById(id.longValue())
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        if (!isAdmin(authentication) && !authentication.getName().equals(user.getCreatedBy())) {
            throw new AccessDeniedException(
                    "Доступ запрещён: можно управлять только пользователями, которых вы создали сами.");
        }
        return user;
    }

    private boolean isAdmin(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    private Set<RoleEntity> resolveRoles(Set<String> roleNames) {
        Set<RoleEntity> roles = new HashSet<>();
        for (String name : roleNames) {
            RoleEntity role = roleRepository.findByName(name)
                    .orElseThrow(() -> new IllegalArgumentException("Role not found: " + name));
            roles.add(role);
        }
        return roles;
    }

    private void validateRolesAssignable(Set<RoleEntity> roles, Authentication authentication) {
        if (isAdmin(authentication)) return;
        for (RoleEntity role : roles) {
            if (PROTECTED_ROLES_FOR_ADMIN_CLIENT.contains(role.getName())) {
                throw new AccessDeniedException(
                        "Роль '" + role.getName() + "' недоступна для назначения через внешний API. " +
                                "Системные роли может назначать только ADMIN.");
            }
        }
    }

    private ExternalUserDto toDto(UserEntity user) {
        ExternalUserDto dto = new ExternalUserDto();
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
        dto.setCreatedBy(user.getCreatedBy());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setRoles(user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()));
        return dto;
    }

    private ExternalServiceUserResponse toServiceUserResponse(UserEntity user, ClientRegistrationResponse clientResponse) {
        ExternalServiceUserResponse dto = new ExternalServiceUserResponse();
        dto.setId(user.getId());
        dto.setClientId(clientResponse.getClientId());
        dto.setClientSecret(clientResponse.getClientSecret());
        dto.setUsername(user.getUsername());
        dto.setDisplayName(user.getDisplayName());
        dto.setEmail(user.getEmail());
        dto.setEnabled(user.getEnabled());
        dto.setAccountNonExpired(user.getAccountNonExpired());
        dto.setAccountNonLocked(user.getAccountNonLocked());
        dto.setExpirationDate(user.getExpirationDate());
        dto.setLastLogon(user.getLastLogon());
        dto.setUserType(user.getUserType());
        dto.setCreatedBy(user.getCreatedBy());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setRoles(user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()));
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
