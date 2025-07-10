package me.rightsflow.auth.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

@Component
@Slf4j
public class RfAuthAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        String username = request.getParameter("username");
        log.warn("Authentication failed for user: {} at {} - {}",
                username, LocalDateTime.now(), exception.getMessage());

        String errorMessage = getErrorMessage(exception);
        String redirectUrl = "/login?error=true&message=" + URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    private String getErrorMessage(AuthenticationException exception) {
        if (exception instanceof BadCredentialsException) {
            return "Неверное имя пользователя или пароль";
        } else if (exception instanceof DisabledException) {
            return "Учетная запись отключена";
        } else if (exception instanceof LockedException) {
            return "Учетная запись заблокирована";
        } else {
            return "Ошибка аутентификации";
        }
    }
}

