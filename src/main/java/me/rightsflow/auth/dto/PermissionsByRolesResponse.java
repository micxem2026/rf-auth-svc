package me.rightsflow.auth.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ответ на запрос {@code GET /api/permissions/by-roles}.
 *
 * <p>Используется микросервисами для наполнения локального кэша прав.
 * Содержит только права запрошенного сервиса (поле service) в виде
 * Map: roleName → List&lt;"resource:action"&gt;.</p>
 *
 * <p>Пример ответа:</p>
 * <pre>
 * {
 *   "service": "rf-contract-svc",
 *   "permissions": {
 *     "MANAGER": ["ContractController:createContract", "ContractController:getContract"],
 *     "VIEWER":  ["ContractController:getContract"]
 *   }
 * }
 * </pre>
 */
@Data
public class PermissionsByRolesResponse {

    /** Имя сервиса, для которого возвращены права */
    private String service;

    /**
     * Права по ролям: roleName → список "resource:action".
     * <p>
     * Все запрошенные роли присутствуют в Map, даже если у роли нет прав
     * (в этом случае — пустой список). Это позволяет кэшу отличить
     * "роль без прав" от "роль не запрашивалась".
     */
    private Map<String, List<String>> permissions;

    public static PermissionsByRolesResponse of(String service, Map<String, List<String>> permissions) {
        PermissionsByRolesResponse response = new PermissionsByRolesResponse();
        response.setService(service);
        response.setPermissions(permissions);
        return response;
    }
}
