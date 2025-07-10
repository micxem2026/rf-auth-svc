package me.rightsflow.auth.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Controller
@Slf4j
public class AuthController {

    private final RegisteredClientRepository registeredClientRepository;

    public AuthController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "logout", required = false) String logout,
            @RequestParam(value = "message", required = false) String message,
            // OAuth2 Authorization Code Flow параметры
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "prompt", required = false) String prompt,
            @RequestParam(value = "max_age", required = false) String maxAge,
            Model model,
            HttpServletRequest request,
            HttpSession session) {

        log.debug("Login page accessed from IP: {}", getClientIpAddress(request));

        // Обработка OAuth2 параметров
        Map<String, String> oauthParams = extractOAuthParameters(request);
        if (!oauthParams.isEmpty()) {
            log.info("OAuth2 authorization request: client_id={}, scope={}, redirect_uri={}",
                    clientId, scope, redirectUri);

            // Сохраняем OAuth2 параметры в сессии для использования после аутентификации
            session.setAttribute("oauth2_params", oauthParams);

            // Добавляем информацию о клиенте в модель для отображения
            model.addAttribute("isOAuthRequest", true);
            model.addAttribute("clientId", clientId);
            model.addAttribute("requestedScopes", parseScopes(scope));
            model.addAttribute("redirectUri", redirectUri);

            // Валидация обязательных параметров для Authorization Code flow
            if ("code".equals(responseType)) {
                String validationError = validateAuthorizationRequest(clientId, redirectUri, scope);
                if (validationError != null) {
                    model.addAttribute("error", true);
                    model.addAttribute("errorMessage", validationError);
                    log.warn("Invalid OAuth2 authorization request: {}", validationError);
                }
            }
        }

        // Обработка обычных параметров логина
        if (error != null) {
            model.addAttribute("error", true);
            model.addAttribute("errorMessage", message != null ? message : "Ошибка аутентификации");
        }

        if (logout != null) {
            model.addAttribute("logout", true);
            model.addAttribute("logoutMessage", "Вы успешно вышли из системы");
        }

        return "login";
    }

    @GetMapping("/oauth2/authorize")
    public String authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("scope") String scope,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @RequestParam(value = "nonce", required = false) String nonce,
            HttpServletRequest request,
            HttpSession session) {

        log.info("OAuth2 authorize endpoint called: client_id={}, response_type={}, scope={}",
                clientId, responseType, scope);

        // Сохраняем все параметры для передачи на страницу логина
        Map<String, String> params = new HashMap<>();
        params.put("response_type", responseType);
        params.put("client_id", clientId);
        params.put("scope", scope);
        params.put("redirect_uri", redirectUri);
        if (state != null) params.put("state", state);
        if (codeChallenge != null) params.put("code_challenge", codeChallenge);
        if (codeChallengeMethod != null) params.put("code_challenge_method", codeChallengeMethod);
        if (nonce != null) params.put("nonce", nonce);

        session.setAttribute("oauth2_params", params);

        // Формируем URL для редиректа на страницу логина с параметрами
        StringBuilder loginUrl = new StringBuilder("/login");
        loginUrl.append("?response_type=").append(responseType);
        loginUrl.append("&client_id=").append(clientId);
        loginUrl.append("&scope=").append(scope);
        loginUrl.append("&redirect_uri=").append(redirectUri);
        if (state != null) loginUrl.append("&state=").append(state);
        if (codeChallenge != null) loginUrl.append("&code_challenge=").append(codeChallenge);
        if (codeChallengeMethod != null) loginUrl.append("&code_challenge_method=").append(codeChallengeMethod);
        if (nonce != null) loginUrl.append("&nonce=").append(nonce);

        return "redirect:" + loginUrl;
    }

    @GetMapping("/callback")
    public String callback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state,
            Model model,
            HttpServletRequest request) {

        log.info("OAuth2 callback received: code={}, state={}", code, state);

        // Формируем полный redirect URI
        String redirectUri = request.getScheme() + "://" + request.getHeader("host") + request.getRequestURI();

        model.addAttribute("code", code);
        model.addAttribute("state", state);
        model.addAttribute("host", request.getHeader("Host"));
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("message", "Код авторизации успешно получен");

        // Добавляем дополнительную информацию для отладки
        model.addAttribute("receivedAt", java.time.LocalDateTime.now().toString());
        model.addAttribute("clientIp", getClientIpAddress(request));

        log.debug("Callback processed successfully, redirecting to home page");

        return "home";
    }

    @GetMapping("/")
    public String homePage(Model model, HttpServletRequest request) {
        model.addAttribute("host", request.getHeader("Host"));
        model.addAttribute("message", "Добро пожаловать в Authorization Server");
        return "home";
    }

    private Map<String, String> extractOAuthParameters(HttpServletRequest request) {
        Map<String, String> params = new HashMap<>();

        String[] oauthParamNames = {
                "response_type", "client_id", "scope", "redirect_uri", "state",
                "code_challenge", "code_challenge_method", "nonce", "prompt", "max_age"
        };

        for (String paramName : oauthParamNames) {
            String paramValue = request.getParameter(paramName);
            if (StringUtils.hasText(paramValue)) {
                try {
                    // Декодируем URL-encoded параметры
                    paramValue = URLDecoder.decode(paramValue, StandardCharsets.UTF_8);
                    params.put(paramName, paramValue);
                } catch (Exception e) {
                    log.warn("Error decoding parameter {}: {}", paramName, e.getMessage());
                    params.put(paramName, paramValue); // Используем как есть, если декодирование не удалось
                }
            }
        }

        return params;
    }

    private String[] parseScopes(String scope) {
        if (!StringUtils.hasText(scope)) {
            return new String[0];
        }
        return scope.split("\\s+");
    }

    private String validateAuthorizationRequest(String clientId, String redirectUri, String scope) {
        // Проверка обязательных параметров
        if (!StringUtils.hasText(clientId)) {
            return "Отсутствует обязательный параметр: client_id";
        }

        if (!StringUtils.hasText(redirectUri)) {
            return "Отсутствует обязательный параметр: redirect_uri";
        }

        RegisteredClient client = registeredClientRepository.findByClientId(clientId);

        if (client == null) {
            return "Неизвестный client_id: %s".formatted(clientId);
        }

        if (!client.getRedirectUris().contains(redirectUri)) {
            return "redirect_uri: %s не зарегистрирован для client_id: %s".formatted(redirectUri, clientId);
        }

        if (!client.getScopes().containsAll(Arrays.asList(scope.split("\\s+")))) {
            return "scope: %s не зарегистрирован для client_id: %s".formatted(scope, clientId);
        }

        return null; // Валидация прошла успешно
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
