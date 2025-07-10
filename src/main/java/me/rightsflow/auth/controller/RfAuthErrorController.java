package me.rightsflow.auth.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Arrays;

@Controller
@Slf4j
public class RfAuthErrorController implements ErrorController {

    @Autowired
    private Environment environment;

    @RequestMapping("/error")
    public String handleError(
            HttpServletRequest request,
            Model model,
            @RequestParam(value = "type", required = false) String type) {

        // Получаем информацию об ошибке из request attributes
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        Object exception = request.getAttribute(RequestDispatcher.ERROR_EXCEPTION);
        Object message = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        Object requestUri = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);

        log.error("Error occurred: status={}, uri={}, exception={}, message={}, type={}",
                status, requestUri, exception, message, type);

        // Определяем тип ошибки
        String errorType = determineErrorType(status, type);

        // Устанавливаем атрибуты модели в зависимости от типа ошибки
        setErrorAttributes(model, errorType, status, message);

        // Добавляем информацию о режиме разработки
        boolean isDevelopment = Arrays.asList(environment.getActiveProfiles()).contains("dev");
        model.addAttribute("showDebugInfo", isDevelopment);

        return "error";
    }

    private String determineErrorType(Object status, String type) {
        // Если тип явно указан в параметре, используем его
        if (type != null) {
            return type;
        }

        // Определяем тип по HTTP статусу
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());

            switch (statusCode) {
                case 400:
                    return "bad-request";
                case 401:
                    return "unauthorized";
                case 403:
                    return "access-denied";
                case 404:
                    return "not-found";
                case 500:
                    return "server-error";
                case 502:
                    return "bad-gateway";
                case 503:
                    return "service-unavailable";
                default:
                    return "general";
            }
        }

        return "general";
    }

    private void setErrorAttributes(Model model, String errorType, Object status, Object message) {
        switch (errorType) {
            case "bad-request":
                model.addAttribute("errorTitle", "Неверный запрос");
                model.addAttribute("errorMessage", "Запрос содержит неверные параметры");
                model.addAttribute("errorCode", "400");
                break;

            case "unauthorized":
                model.addAttribute("errorTitle", "Требуется аутентификация");
                model.addAttribute("errorMessage", "Для доступа к ресурсу необходимо войти в систему");
                model.addAttribute("errorCode", "401");
                break;

            case "access-denied":
                model.addAttribute("errorTitle", "Доступ запрещен");
                model.addAttribute("errorMessage", "У вас нет прав для доступа к этому ресурсу");
                model.addAttribute("errorCode", "403");
                break;

            case "not-found":
                model.addAttribute("errorTitle", "Страница не найдена");
                model.addAttribute("errorMessage", "Запрашиваемая страница не существует");
                model.addAttribute("errorCode", "404");
                break;

            case "server-error":
                model.addAttribute("errorTitle", "Внутренняя ошибка сервера");
                model.addAttribute("errorMessage", "Произошла внутренняя ошибка сервера");
                model.addAttribute("errorCode", "500");
                break;

            case "bad-gateway":
                model.addAttribute("errorTitle", "Ошибка шлюза");
                model.addAttribute("errorMessage", "Получен неверный ответ от вышестоящего сервера");
                model.addAttribute("errorCode", "502");
                break;

            case "service-unavailable":
                model.addAttribute("errorTitle", "Сервис недоступен");
                model.addAttribute("errorMessage", "Сервис временно недоступен");
                model.addAttribute("errorCode", "503");
                break;

            // OAuth2 специфичные ошибки
            case "invalid-client":
                model.addAttribute("errorTitle", "Неверный клиент");
                model.addAttribute("errorMessage", "Указанный клиент не найден или неактивен");
                model.addAttribute("errorCode", "400");
                break;

            case "invalid-redirect-uri":
                model.addAttribute("errorTitle", "Неверный redirect URI");
                model.addAttribute("errorMessage", "Указанный redirect URI не зарегистрирован для данного клиента");
                model.addAttribute("errorCode", "400");
                break;

            case "unsupported-response-type":
                model.addAttribute("errorTitle", "Неподдерживаемый тип ответа");
                model.addAttribute("errorMessage", "Указанный response_type не поддерживается");
                model.addAttribute("errorCode", "400");
                break;

            case "invalid-scope":
                model.addAttribute("errorTitle", "Неверная область доступа");
                model.addAttribute("errorMessage", "Запрашиваемая область доступа недоступна для данного клиента");
                model.addAttribute("errorCode", "400");
                break;

            case "access-denied-oauth":
                model.addAttribute("errorTitle", "Авторизация отклонена");
                model.addAttribute("errorMessage", "Пользователь отклонил запрос на авторизацию");
                model.addAttribute("errorCode", "400");
                break;

            default:
                model.addAttribute("errorTitle", "Произошла ошибка");
                model.addAttribute("errorMessage",
                        message != null ? message.toString() : "Произошла неизвестная ошибка");
                model.addAttribute("errorCode", status != null ? status.toString() : "");
        }

        // Добавляем дополнительную информацию
        model.addAttribute("errorType", errorType);
        model.addAttribute("showBackButton", !errorType.equals("unauthorized"));
        model.addAttribute("showLoginButton", errorType.equals("unauthorized") || errorType.equals("access-denied"));
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
