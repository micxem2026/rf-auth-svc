package me.rightsflow.auth.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@Slf4j
public class RfAuthLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        log.debug("=================================================");
        if (authentication != null) {
            log.info("User {} logged out successfully at {} from IP: {}",
                    authentication.getName(), LocalDateTime.now(), getClientIpAddress(request));
        }

        // Очищаем OAuth2 параметры из сессии
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute("oauth2_params");
            log.debug("Cleared OAuth2 parameters from session");
        }

        // Проверяем, есть ли кастомный redirect_uri
        String redirectUrl = determineRedirectUrl(request.getParameter("redirect_uri"));

        log.debug("Redirecting after logout to: {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    private String determineRedirectUrl(String redirectUri) {
        log.debug("REDIRECT_URI: {}", redirectUri);
        // Если указан redirect_uri, проверя его и используем
        if (redirectUri != null && !redirectUri.trim().isEmpty()) {
            // TODO: Добавить валидацию redirect_uri для безопасности
            // Пока что разрешаем только локальные redirect'ы
            if (redirectUri.startsWith("/")) {
                return redirectUri;
            }
        }

        // По умолчанию редиректим на страницу логина с параметром logout
        return "/auth/login?logout=true";
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}
