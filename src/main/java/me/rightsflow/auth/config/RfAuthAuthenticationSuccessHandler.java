package me.rightsflow.auth.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

@Component
@Slf4j
public class RfAuthAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    // Добавляем RequestCache для работы с сохраненными запросами
    private final RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        log.info("Successful authentication for user: {} at {}", authentication.getName(), LocalDateTime.now());

        HttpSession session = request.getSession(false);

        // 1. Проверяем, есть ли OAuth2 параметры в сессии (эта логика остается)
        if (session != null) {
            @SuppressWarnings("unchecked")
            Map<String, String> oauthParams = (Map<String, String>) session.getAttribute("oauth2_params");

            if (oauthParams != null && !oauthParams.isEmpty()) {
                log.info("Processing OAuth2 authorization for user: {}, client_id: {}",
                        authentication.getName(), oauthParams.get("client_id"));
                session.removeAttribute("oauth2_params");
                String authorizationUrl = buildAuthorizationUrl(oauthParams);
                log.debug("Redirecting to OAuth2 authorization endpoint: {}", authorizationUrl);
                getRedirectStrategy().sendRedirect(request, response, authorizationUrl);
                return;
            }
        }

        // 2. Проверяем, есть ли сохраненный запрос от Spring Security
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            // Удаляем сохраненный запрос, чтобы избежать повторного использования
            requestCache.removeRequest(request, response);
            String targetUrl = savedRequest.getRedirectUrl();
            log.debug("Saved request found. Redirecting to: {}", targetUrl);

            // ВАЖНО: Если сохраненный URL ведет на API, перенаправляем на UI
            if (targetUrl.contains("/api/")) {
                log.warn("Saved request URL '{}' points to an API endpoint. Redirecting to a default page instead.", targetUrl);
                determineAndRedirect(request, response, authentication);
                return;
            }

            // Если URL безопасен, используем стандартное поведение
            super.onAuthenticationSuccess(request, response, authentication);
            return;
        }

        // 3. Если нет ни OAuth2, ни сохраненного запроса, решаем куда перенаправить на основе роли
        determineAndRedirect(request, response, authentication);
    }

    /**
     * Определяет URL для перенаправления на основе роли пользователя и выполняет редирект.
     */
    private void determineAndRedirect(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        String targetUrl = determineTargetUrl(authentication);
        log.debug("No saved request. Redirecting user {} to role-based target URL: {}", authentication.getName(), targetUrl);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
        clearAuthenticationAttributes(request);
    }

    /**
     * Определяет целевой URL на основе ролей пользователя.
     * @param authentication объект аутентификации
     * @return URL для перенаправления
     */
    protected String determineTargetUrl(final Authentication authentication) {
        boolean isAdmin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch("ROLE_ADMIN"::equals);

        if (isAdmin) {
            return "/"; // Администраторов на страницу управления клиентами
        } else {
            return "/"; // Всех остальных на главную
        }
    }

    private String buildAuthorizationUrl(Map<String, String> oauthParams) {
        StringBuilder url = new StringBuilder("/oauth2/authorize");

        boolean first = true;
        for (Map.Entry<String, String> entry : oauthParams.entrySet()) {
            if (StringUtils.hasText(entry.getValue())) {
                url.append(first ? "?" : "&");
                url.append(entry.getKey()).append("=");
                url.append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
                first = false;
            }
        }

        return url.toString();
    }
}
