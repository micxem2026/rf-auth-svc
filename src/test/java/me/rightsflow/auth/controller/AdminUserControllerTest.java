package me.rightsflow.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.rightsflow.auth.config.TestSecurityConfig;
import me.rightsflow.auth.dto.RoleDto;
import me.rightsflow.auth.dto.UserDto;
import me.rightsflow.auth.dto.UserRequestDto;
import me.rightsflow.auth.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AdminUserController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
@DisplayName("AdminUserController")
class AdminUserControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockitoBean UserService userService;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private UserDto makeUserDto(Integer id, String username) {
        UserDto dto = new UserDto();
        dto.setId(id);
        dto.setUsername(username);
        dto.setDisplayName(username);
        dto.setEmail(username + "@test.com");
        dto.setEnabled(true);
        dto.setAccountNonExpired(true);
        dto.setAccountNonLocked(true);
        dto.setUserType("USER");
        dto.setRoles(Set.of("USER"));
        dto.setProtectedUser(false);
        return dto;
    }

    private RoleDto makeRoleDto(Integer id, String name, String createdBy) {
        RoleDto dto = new RoleDto();
        dto.setId(id);
        dto.setName(name);
        dto.setDescription("desc");
        dto.setCreatedBy(createdBy);
        return dto;
    }

    // ================================================================
    // GET /admin/api/users
    // ================================================================

    @Nested @DisplayName("GET /admin/api/users")
    class GetUsers {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN получает список пользователей")
        void adminGetsUsers() throws Exception {
            when(userService.getAllUsers())
                    .thenReturn(List.of(makeUserDto(1, "admin"), makeUserDto(2, "john")));

            mockMvc.perform(get("/admin/api/users"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(2));
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("MANAGER не имеет доступа к списку пользователей")
        void managerIsForbidden() throws Exception {
            mockMvc.perform(get("/admin/api/users"))
                    .andExpect(status().isForbidden());
        }

        @Test
        @DisplayName("Анонимный пользователь перенаправляется")
        void anonymousIsRedirected() throws Exception {
            mockMvc.perform(get("/admin/api/users"))
                    .andExpect(status().is3xxRedirection());
        }
    }

    // ================================================================
    // POST /admin/api/users
    // ================================================================

    @Nested @DisplayName("POST /admin/api/users")
    class CreateUser {

        private UserRequestDto validRequest() {
            UserRequestDto r = new UserRequestDto();
            r.setUsername("newuser");
            r.setDisplayName("New User");
            r.setEmail("new@test.com");
            r.setPassword("password123");
            r.setEnabled(true);
            r.setAccountNonExpired(true);
            r.setAccountNonLocked(true);
            r.setRoles(Set.of());
            return r;
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN создаёт пользователя")
        void adminCreatesUser() throws Exception {
            when(userService.createUser(any())).thenReturn(makeUserDto(3, "newuser"));

            mockMvc.perform(post("/admin/api/users")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.username").value("newuser"));
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Валидация — пустой username возвращает 400")
        void emptyUsernameReturns400() throws Exception {
            UserRequestDto req = validRequest();
            req.setUsername("");

            mockMvc.perform(post("/admin/api/users")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Дублирующий username возвращает 400")
        void duplicateUsernameReturns400() throws Exception {
            when(userService.createUser(any()))
                    .thenThrow(new IllegalArgumentException("Username already exists"));

            mockMvc.perform(post("/admin/api/users")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(validRequest())))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").exists());
        }
    }

    // ================================================================
    // DELETE /admin/api/users/{id}
    // ================================================================

    @Nested @DisplayName("DELETE /admin/api/users/{id}")
    class DeleteUser {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN удаляет пользователя")
        void adminDeletesUser() throws Exception {
            doNothing().when(userService).deleteUser(2);

            mockMvc.perform(delete("/admin/api/users/2").with(csrf()))
                    .andExpect(status().isNoContent());
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Попытка удалить защищённого пользователя возвращает 400")
        void deleteProtectedUserReturns400() throws Exception {
            doThrow(new IllegalArgumentException("Нельзя удалить системного пользователя"))
                    .when(userService).deleteUser(1);

            mockMvc.perform(delete("/admin/api/users/1").with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").exists());
        }
    }

    // ================================================================
    // GET /admin/api/roles
    // ================================================================

    @Nested @DisplayName("GET /admin/api/roles")
    class GetRoles {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN получает список ролей")
        void adminGetsRoles() throws Exception {
            when(userService.getAllRoles()).thenReturn(List.of(
                    makeRoleDto(1, "ADMIN", "system"),
                    makeRoleDto(2, "USER", "system")));

            mockMvc.perform(get("/admin/api/roles"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(2));
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("PERMISSION_MANAGER получает список ролей")
        void pmGetsRoles() throws Exception {
            when(userService.getAllRoles()).thenReturn(List.of(
                    makeRoleDto(10, "ANALYST", "user1")));

            mockMvc.perform(get("/admin/api/roles"))
                    .andExpect(status().isOk());
        }
    }

    // ================================================================
    // POST /admin/api/roles
    // ================================================================

    @Nested @DisplayName("POST /admin/api/roles")
    class CreateRole {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN создаёт роль")
        void adminCreatesRole() throws Exception {
            RoleDto req = new RoleDto();
            req.setName("ANALYST");
            req.setDescription("Аналитик");

            when(userService.createRole(any())).thenReturn(makeRoleDto(10, "ANALYST", "admin"));

            mockMvc.perform(post("/admin/api/roles")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.name").value("ANALYST"));
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("PERMISSION_MANAGER создаёт роль")
        void pmCreatesRole() throws Exception {
            RoleDto req = new RoleDto();
            req.setName("ANALYST");

            when(userService.createRole(any())).thenReturn(makeRoleDto(10, "ANALYST", "user1"));

            mockMvc.perform(post("/admin/api/roles")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isCreated());
        }

        @Test
        @WithMockUser(roles = "USER")
        @DisplayName("USER не имеет доступа к созданию роли")
        void userIsForbidden() throws Exception {
            RoleDto req = new RoleDto();
            req.setName("ANALYST");

            mockMvc.perform(post("/admin/api/roles")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Дублирующая роль возвращает 400")
        void duplicateRoleReturns400() throws Exception {
            RoleDto req = new RoleDto();
            req.setName("ADMIN");

            when(userService.createRole(any()))
                    .thenThrow(new IllegalArgumentException("Role already exists: ADMIN"));

            mockMvc.perform(post("/admin/api/roles")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").value("Role already exists: ADMIN"));
        }
    }

    // ================================================================
    // POST /admin/api/users/{userId}/roles/{roleId} — назначение роли
    // ================================================================

    @Nested @DisplayName("POST /admin/api/users/{userId}/roles/{roleId}")
    class AssignRole {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN назначает роль пользователю")
        void adminAssignsRole() throws Exception {
            when(userService.assignRoleToUser(eq(2), eq(10), any()))
                    .thenReturn(makeUserDto(2, "john"));

            mockMvc.perform(post("/admin/api/users/2/roles/10").with(csrf()))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("PERMISSION_MANAGER назначает роль")
        void pmAssignsRole() throws Exception {
            when(userService.assignRoleToUser(eq(2), eq(10), any()))
                    .thenReturn(makeUserDto(2, "john"));

            mockMvc.perform(post("/admin/api/users/2/roles/10").with(csrf()))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("Назначение чужой роли возвращает 400")
        void assignForeignRoleReturns400() throws Exception {
            when(userService.assignRoleToUser(eq(2), eq(1), any()))
                    .thenThrow(new IllegalArgumentException("Вы можете назначать только роли, которые создали сами."));

            mockMvc.perform(post("/admin/api/users/2/roles/1").with(csrf()))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").exists());
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("MANAGER не имеет доступа к назначению ролей")
        void managerIsForbiddenToAssign() throws Exception {
            // /admin/api/users/*/roles/* требует ADMIN или PERMISSION_MANAGER
            mockMvc.perform(post("/admin/api/users/2/roles/10").with(csrf()))
                    .andExpect(status().isForbidden());
        }
    }

    // ================================================================
    // DELETE /admin/api/users/{userId}/roles/{roleId} — снятие роли
    // ================================================================

    @Nested @DisplayName("DELETE /admin/api/users/{userId}/roles/{roleId}")
    class RevokeRole {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN снимает роль")
        void adminRevokesRole() throws Exception {
            when(userService.revokeRoleFromUser(eq(2), eq(10), any()))
                    .thenReturn(makeUserDto(2, "john"));

            mockMvc.perform(delete("/admin/api/users/2/roles/10").with(csrf()))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("Снятие незназначенной роли возвращает 400")
        void revokeNotAssignedReturns400() throws Exception {
            when(userService.revokeRoleFromUser(eq(2), eq(10), any()))
                    .thenThrow(new IllegalArgumentException("Роль не назначена пользователю"));

            mockMvc.perform(delete("/admin/api/users/2/roles/10").with(csrf()))
                    .andExpect(status().isBadRequest());
        }
    }
}
