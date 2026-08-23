package me.rightsflow.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.dto.LoginRequest;
import me.rightsflow.auth.dto.LoginResponse;
import me.rightsflow.auth.service.ExternalAuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth/v1")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Аутентификация", description = "Аутентификация внешних пользователей")
public class ExternalAuthController {

    private final ExternalAuthService externalAuthService;
    private final WebAuthenticationDetailsSource detailsSource = new WebAuthenticationDetailsSource();

    /**
     * Логин внешнего клиента.
     * Возвращает JWT, который принимается всеми ресурс-серверами платформы
     * (тот же механизм проверки, что и у обычных OAuth2-токенов).
     */
    @Operation(summary = "Получение токена для заданного пользователя")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        try {
            WebAuthenticationDetails details = detailsSource.buildDetails(httpRequest);
            LoginResponse response = externalAuthService.login(request, details);
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException | UsernameNotFoundException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Неверный логин или пароль."));
        } catch (DisabledException | LockedException | AccountExpiredException | CredentialsExpiredException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", e.getMessage()));
        } catch (AuthenticationException e) {
            log.warn("Unexpected authentication error", e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Ошибка аутентификации."));
        }
    }
}
