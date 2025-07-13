package me.rightsflow.auth.controller;

import lombok.RequiredArgsConstructor;
import me.rightsflow.auth.service.ClientRegistrationService;
import me.rightsflow.auth.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final ClientRegistrationService clientRegistrationService;
    private final UserService userService;

    @GetMapping("/clients")
    public String clientsPage(Model model) {
        model.addAttribute("clients", clientRegistrationService.getUserClients());
        model.addAttribute("title", "Управление OAuth2 клиентами");
        return "admin/clients";
    }

    @GetMapping("/clients/register")
    public String registerClientPage(Model model) {
        model.addAttribute("title", "Регистрация нового клиента");
        return "admin/register-client";
    }

    @GetMapping("/users")
    public String usersPage(Model model) {
        model.addAttribute("roles", userService.getAllRoles()); // Передаем роли для форм
        model.addAttribute("title", "Управление пользователями и ролями");
        return "admin/users";
    }
}

