package me.rightsflow.auth.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;

@Component
@Slf4j
public class RfAuthAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        log.info("Successful authentication for user: {} at {}",
                authentication.getName(), LocalDateTime.now());

        HttpSession session = request.getSession(false);

        // Проверяем, есть ли OAuth2 параметры в сессии
        if (session != null) {
            @SuppressWarnings("unchecked")
            Map<String, String> oauthParams = (Map<String, String>) session.getAttribute("oauth2_params");

            if (oauthParams != null && !oauthParams.isEmpty()) {
                log.info("Processing OAuth2 authorization for user: {}, client_id: {}",
                        authentication.getName(), oauthParams.get("client_id"));

                // Очищаем OAuth2 параметры из сессии
                session.removeAttribute("oauth2_params");

                // Формируем URL для перенаправления на authorization endpoint
                String authorizationUrl = buildAuthorizationUrl(oauthParams);

                log.debug("Redirecting to OAuth2 authorization endpoint: {}", authorizationUrl);
                response.sendRedirect(authorizationUrl);
                return;
            }
        }

        // Стандартное поведение для обычной аутентификации
        super.onAuthenticationSuccess(request, response, authentication);
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
