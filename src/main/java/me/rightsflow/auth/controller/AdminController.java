package me.rightsflow.auth.controller;

import lombok.RequiredArgsConstructor;
import me.rightsflow.auth.service.ClientRegistrationService;
import me.rightsflow.auth.service.PermissionService;
import me.rightsflow.auth.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final ClientRegistrationService clientRegistrationService;
    private final UserService userService;
    private final PermissionService permissionService;

    @GetMapping("/clients")
    @PreAuthorize("hasRole('ADMIN')")
    public String clientsPage(Model model) {
        model.addAttribute("clients", clientRegistrationService.getUserClients());
        model.addAttribute("title", "Управление OAuth2 клиентами");
        return "admin/clients";
    }

    @GetMapping("/clients/register")
    @PreAuthorize("hasRole('ADMIN')")
    public String registerClientPage(Model model) {
        model.addAttribute("title", "Регистрация нового клиента");
        return "admin/register-client";
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public String usersPage(Model model) {
        model.addAttribute("roles", userService.getAllRoles());
        model.addAttribute("title", "Управление пользователями и ролями");
        return "admin/users";
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public String permissionsPage(Model model, Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        model.addAttribute("services", permissionService.getDistinctServices());
        model.addAttribute("roles", userService.getAllRoles());
        model.addAttribute("isAdmin", isAdmin);
        model.addAttribute("currentUsername", authentication.getName());
        // Флаг: есть ли у PERMISSION_MANAGER хотя бы одна созданная им роль
        boolean hasOwnRoles = isAdmin || userService.getAllRoles().stream()
                .anyMatch(r -> authentication.getName().equals(r.getCreatedBy()));
        model.addAttribute("hasOwnRoles", hasOwnRoles);
        model.addAttribute("title", "Управление правами ролей");
        return "admin/permissions";
    }

    @GetMapping("/permissions/roles/{roleId}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')")
    public String rolePermissionsPage(@PathVariable Integer roleId, Model model) {
        me.rightsflow.auth.dto.RoleDto role = userService.getRoleById(roleId);
        model.addAttribute("role", role);
        model.addAttribute("services", permissionService.getDistinctServices());
        model.addAttribute("isProtected", permissionService.isProtectedRole(role.getName()));
        model.addAttribute("title", "Права роли");
        return "admin/role-permissions";
    }
}
