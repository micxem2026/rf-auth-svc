package me.rightsflow.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.ClientRegistrationRequest;
import me.rightsflow.auth.dto.ClientRegistrationResponse;
import me.rightsflow.auth.service.ClientRegistrationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/admin/api/clients")
@RequiredArgsConstructor
@Slf4j
@PreAuthorize("hasRole('ADMIN')")
public class ClientRegistrationController {

    private final ClientRegistrationService clientRegistrationService;

    @PostMapping
    public ResponseEntity<?> registerClient(
            @Valid @RequestBody ClientRegistrationRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        log.debug("=== CLIENT REGISTRATION REQUEST ===");
        log.debug("User: {}", authentication.getName());
        log.debug("Roles: {}", authentication.getAuthorities());
        log.debug("Client ID: {}", request.getClientId());
        log.debug("Client Name: {}", request.getClientName());
        log.debug("Grant Types: {}", request.getGrantTypes());
        log.debug("Scopes: {}", request.getScopes());
        log.debug("Request Headers: {}", Collections.list(httpRequest.getHeaderNames()).stream()
                .collect(Collectors.toMap(h -> h, httpRequest::getHeader)));

        try {
            ClientRegistrationResponse response = clientRegistrationService.registerClient(request, authentication);
            log.info("Client registered successfully: {} by {}", request.getClientId(), authentication.getName());
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            log.warn("Client registration failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during client registration", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error: " + e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<List<ClientRegistrationResponse>> getClients() {
        List<ClientRegistrationResponse> clients = clientRegistrationService.getUserClients();
        return ResponseEntity.ok(clients);
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<?> deleteClient(
            @PathVariable String clientId,
            Authentication authentication) {

        try {
            clientRegistrationService.deleteClient(clientId, authentication);
            log.info("Client deleted successfully: {} by {}", clientId, authentication.getName());
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            log.warn("Client deletion failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during client deletion", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error"));
        }
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<?> getClient(@PathVariable String clientId, Authentication authentication) {
        try {
            ClientRegistrationResponse client = clientRegistrationService.getClientById(clientId, authentication);
            log.debug("Client retrieved successfully: {} ", client);
            return ResponseEntity.ok(client);
        } catch (IllegalArgumentException e) {
            log.warn("Client retrieval failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during client retrieval", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error"));
        }
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<?> updateClient(
            @PathVariable String clientId,
            @Valid @RequestBody ClientRegistrationRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {

        log.debug("=== CLIENT UPDATE REQUEST ===");
        log.debug("User: {}", authentication.getName());
        log.debug("Client ID: {}", clientId);
        log.debug("Update data: {}", request);

        try {
            ClientRegistrationResponse response = clientRegistrationService.updateClient(clientId, request, authentication);
            log.info("Client updated successfully: {} by {}", clientId, authentication.getName());
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            log.warn("Client update failed: {}", e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Unexpected error during client update", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Internal server error: " + e.getMessage()));
        }
    }

    /**
     * Установить/снять флаг защиты клиента.
     * Только ADMIN.
     */
    @PatchMapping("/{clientId}/protected")
    public ResponseEntity<?> setProtected(
            @PathVariable String clientId,
            @RequestParam boolean value,
            Authentication authentication) {
        try {
            clientRegistrationService.setProtectedFlag(clientId, value, authentication);
            log.info("Client '{}' protected={} by {}", clientId, value, authentication.getName());
            return ResponseEntity.ok(Map.of("clientId", clientId, "protected", value));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
