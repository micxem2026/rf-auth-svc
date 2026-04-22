package me.rightsflow.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.rightsflow.auth.config.TestSecurityConfig;
import me.rightsflow.auth.dto.PermissionDto;
import me.rightsflow.auth.dto.PermissionsByRolesResponse;
import me.rightsflow.auth.dto.RolePermissionDto;
import me.rightsflow.auth.service.PermissionService;
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
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = PermissionController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("test")
@DisplayName("PermissionController")
// TestSecurityConfig подменяет основной SecurityFilterChain через @Primary.
// Но @WebMvcTest может подтянуть и другие @Configuration-классы.
// Неаутентифицированные запросы получают 302 (редирект на /login),
// поэтому тесты на "запрещённый доступ" используют WithMockUser с неподходящей ролью.
class PermissionControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockitoBean PermissionService permissionService;

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    private PermissionDto makePermDto(Integer id, String service,
                                       String resource, String action) {
        PermissionDto dto = new PermissionDto();
        dto.setId(id);
        dto.setService(service);
        dto.setResource(resource);
        dto.setAction(action);
        return dto;
    }

    // ================================================================
    // GET /api/permissions/by-roles — загрузка кэша микросервисами
    // ================================================================

    @Nested @DisplayName("GET /api/permissions/by-roles")
    class ByRoles {

        @Test
        @WithMockUser  // любой аутентифицированный
        @DisplayName("Аутентифицированный клиент получает права")
        void authenticatedClientGetsPermissions() throws Exception {
            PermissionsByRolesResponse resp = PermissionsByRolesResponse.of(
                    "rf-contract-svc",
                    Map.of("MANAGER", List.of("ContractController:getContract")));
            when(permissionService.getPermissionsForCache(
                    eq("rf-contract-svc"), anySet())).thenReturn(resp);

            mockMvc.perform(get("/api/permissions/by-roles")
                            .param("service", "rf-contract-svc")
                            .param("roles", "MANAGER"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.service").value("rf-contract-svc"))
                    .andExpect(jsonPath("$.permissions.MANAGER").isArray());
        }

        @Test
        @DisplayName("Анонимный запрос к by-roles перенаправляется")
        void anonymousIsRedirected() throws Exception {
            mockMvc.perform(get("/api/permissions/by-roles")
                            .param("service", "rf-contract-svc")
                            .param("roles", "MANAGER"))
                    .andExpect(status().is3xxRedirection());
        }
    }

    // ================================================================
    // GET /api/permissions — список всех прав
    // ================================================================

    @Nested @DisplayName("GET /api/permissions")
    class GetAll {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN получает все права")
        void adminGetsAllPermissions() throws Exception {
            when(permissionService.getAllPermissions()).thenReturn(List.of(
                    makePermDto(1, "rf-contract-svc", "ContractController", "create"),
                    makePermDto(2, "rf-contract-svc", "ContractController", "get")));

            mockMvc.perform(get("/api/permissions"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.length()").value(2));
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("Пользователь без прав не имеет доступа")
        void userIsForbidden() throws Exception {
            // Аутентифицированный MANAGER не ADMIN и не PM — получает 403
            mockMvc.perform(get("/api/permissions"))
                    .andExpect(status().isForbidden());
        }
    }

    // ================================================================
    // POST /api/permissions — создание права
    // ================================================================

    @Nested @DisplayName("POST /api/permissions")
    class CreatePermission {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN создаёт право")
        void adminCreatesPermission() throws Exception {
            // Все поля без спецсимволов — проходят @Pattern валидацию
            PermissionDto req = makePermDto(null, "rf-contract-svc",
                    "ContractController", "create");

            when(permissionService.createPermission(any()))
                    .thenReturn(makePermDto(1, "rf-contract-svc",
                            "ContractController", "create"));

            mockMvc.perform(post("/api/permissions")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.id").value(1));
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("Пользователь без нужной роли не может создавать права")
        void pmCannotCreatePermission() throws Exception {
            // Запрос валидный — статус определяется только правилом безопасности
            PermissionDto req = makePermDto(null, "rf-contract-svc",
                    "ContractController", "create");

            mockMvc.perform(post("/api/permissions")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isForbidden());
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Дублирующее право возвращает 400")
        void duplicatePermissionReturns400() throws Exception {
            PermissionDto req = makePermDto(null, "rf-contract-svc",
                    "ContractController", "create");

            when(permissionService.createPermission(any()))
                    .thenThrow(new IllegalArgumentException("Permission already exists"));

            mockMvc.perform(post("/api/permissions")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(req)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").exists());
        }
    }

    // ================================================================
    // DELETE /api/permissions/{id}
    // ================================================================

    @Nested @DisplayName("DELETE /api/permissions/{id}")
    class DeletePermission {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN удаляет право")
        void adminDeletesPermission() throws Exception {
            doNothing().when(permissionService).deletePermission(1);

            mockMvc.perform(delete("/api/permissions/1").with(csrf()))
                    .andExpect(status().isNoContent());
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("Пользователь без прав не может удалять права")
        void pmCannotDeletePermission() throws Exception {
            // Аутентифицированный MANAGER не ADMIN и не PM — получает 403 от @PreAuthorize
            mockMvc.perform(delete("/api/permissions/1").with(csrf()))
                    .andExpect(status().isForbidden());
        }

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("Несуществующее право возвращает 400")
        void notFoundReturns400() throws Exception {
            doThrow(new IllegalArgumentException("Permission not found"))
                    .when(permissionService).deletePermission(99);

            mockMvc.perform(delete("/api/permissions/99").with(csrf()))
                    .andExpect(status().isBadRequest());
        }
    }

    // ================================================================
    // GET /api/permissions/roles/{roleId}
    // ================================================================

    @Nested @DisplayName("GET /api/permissions/roles/{roleId}")
    class GetRolePermissions {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN получает права роли")
        void adminGetsRolePermissions() throws Exception {
            RolePermissionDto rp = new RolePermissionDto();
            rp.setRoleId(10);
            rp.setRoleName("ANALYST");
            rp.setPermissionId(1);
            rp.setService("rf-contract-svc");
            rp.setResource("ContractController");
            rp.setAction("getContract");

            when(permissionService.getRolePermissions(10)).thenReturn(List.of(rp));

            mockMvc.perform(get("/api/permissions/roles/10"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$[0].roleName").value("ANALYST"));
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("PERMISSION_MANAGER получает права своей роли")
        void pmGetsOwnRolePermissions() throws Exception {
            when(permissionService.getRolePermissions(10)).thenReturn(List.of());

            mockMvc.perform(get("/api/permissions/roles/10"))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "MANAGER")
        @DisplayName("Пользователь без прав не имеет доступа")
        void userIsForbidden() throws Exception {
            mockMvc.perform(get("/api/permissions/roles/10"))
                    .andExpect(status().isForbidden());
        }
    }

    // ================================================================
    // PUT /api/permissions/roles/{roleId} — массовое обновление
    // ================================================================

    @Nested @DisplayName("PUT /api/permissions/roles/{roleId}")
    class UpdateRolePermissions {

        @Test
        @WithMockUser(roles = "ADMIN")
        @DisplayName("ADMIN обновляет права роли")
        void adminUpdatesRolePermissions() throws Exception {
            doNothing().when(permissionService)
                    .updateRolePermissions(eq(10), anySet(), any());
            when(permissionService.getRolePermissions(10)).thenReturn(List.of());

            mockMvc.perform(put("/api/permissions/roles/10")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("[1, 2, 3]"))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("PERMISSION_MANAGER обновляет права своей роли")
        void pmUpdatesOwnRolePermissions() throws Exception {
            doNothing().when(permissionService)
                    .updateRolePermissions(eq(10), anySet(), any());
            when(permissionService.getRolePermissions(10)).thenReturn(List.of());

            mockMvc.perform(put("/api/permissions/roles/10")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("[1]"))
                    .andExpect(status().isOk());
        }

        @Test
        @WithMockUser(roles = "PERMISSION_MANAGER")
        @DisplayName("Попытка изменить чужую роль возвращает 400")
        void pmCannotUpdateForeignRole() throws Exception {
            doThrow(new IllegalArgumentException("Вы можете управлять правами только тех ролей, которые создали сами."))
                    .when(permissionService).updateRolePermissions(eq(5), anySet(), any());

            mockMvc.perform(put("/api/permissions/roles/5")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("[1]"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").exists());
        }
    }
}
