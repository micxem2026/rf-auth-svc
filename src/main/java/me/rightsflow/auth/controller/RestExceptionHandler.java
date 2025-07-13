package me.rightsflow.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * Глобальный обработчик исключений для всех @RestController.
 * Он перехватывает определенные исключения и форматирует их в виде JSON-ответа,
 * вместо того чтобы позволить Spring перенаправить на HTML-страницу ошибки.
 */
@RestControllerAdvice(basePackages = "me.rightsflow.auth.controller")
public class RestExceptionHandler {

    /**
     * Обрабатывает исключения валидации, возникающие из-за @Valid.
     * Собирает все ошибки полей в Map и возвращает их с HTTP-статусом 400.
     * @param ex Исключение, содержащее ошибки валидации.
     * @return Map, где ключ - имя поля, а значение - сообщение об ошибке.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public Map<String, String> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();

        // Для простоты и совместимости с текущим JS, вернем одну общую ошибку.
        // Берем сообщение из самой первой ошибки валидации.
        String errorMessage = ex.getBindingResult().getAllErrors().get(0).getDefaultMessage();

        errors.put("error", errorMessage);

        return errors;
    }

    /**
     * Обрабатывает общие ошибки бизнес-логики (например, "пользователь уже существует").
     * @param ex Исключение IllegalArgumentException.
     * @return Map с сообщением об ошибке.
     */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(IllegalArgumentException.class)
    public Map<String, String> handleIllegalArgumentException(IllegalArgumentException ex) {
        return Map.of("error", ex.getMessage());
    }

}
