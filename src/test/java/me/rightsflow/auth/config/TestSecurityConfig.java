package me.rightsflow.auth.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

import java.util.UUID;

/**
 * Тестовая конфигурация Spring Security для @WebMvcTest.
 * Заменяет основной SecurityFilterChain через @Primary.
 * <p>
 * Применяет те же правила authorizeHttpRequests что и основной конфиг,
 * но без зависимостей от OAuth2/JWK/Kafka — они не нужны в MVC-тестах.
 * <p>
 * Использование: @Import(TestSecurityConfig.class) в тест-классе.
 * <p>
 * ВАЖНО: @EnableMethodSecurity обязателен — без него @PreAuthorize
 * на методах контроллеров игнорируется и тесты на 403 будут падать.
 */
@TestConfiguration
@EnableWebSecurity
@EnableMethodSecurity
public class TestSecurityConfig {

    @Bean
    @Primary
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/actuator/**", "/error", "/login", "/logout", "/"
                        ).permitAll()

                        // Кэш прав — любой аутентифицированный
                        .requestMatchers("/api/permissions/by-roles")
                        .authenticated()

                        // Управление правами — ADMIN или PERMISSION_MANAGER
                        .requestMatchers("/api/permissions/**").access(
                                new WebExpressionAuthorizationManager(
                                        "hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')"))

                        .requestMatchers("/api/**", "/userinfo").authenticated()

                        // Страницы прав — ADMIN или PM
                        .requestMatchers("/admin/permissions", "/admin/permissions/**").access(
                                new WebExpressionAuthorizationManager(
                                        "hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')"))

                        // API ролей — ADMIN или PM
                        .requestMatchers("/admin/api/roles", "/admin/api/roles/**").access(
                                new WebExpressionAuthorizationManager(
                                        "hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')"))

                        // Сводка пользователей — ADMIN или PM
                        .requestMatchers("/admin/api/users/summary").access(
                                new WebExpressionAuthorizationManager(
                                        "hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')"))

                        // Назначение ролей пользователям — ADMIN или PM
                        .requestMatchers("/admin/api/users/*/roles/*").access(
                                new WebExpressionAuthorizationManager(
                                        "hasRole('ADMIN') or hasRole('PERMISSION_MANAGER')"))

                        // Остальное в /admin — только ADMIN
                        .requestMatchers("/admin/**").hasRole("ADMIN")

                        .anyRequest().authenticated()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(new RfAuthLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                        .permitAll()
                )
                .exceptionHandling(ex -> ex
                        .accessDeniedHandler((req, res, e) ->
                                res.sendError(403))
                        .authenticationEntryPoint((req, res, e) ->
                                res.sendRedirect("/auth/login"))
                )
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * Минимальная заглушка RegisteredClientRepository.
     * Нужна контроллерам которые зависят от OAuth2-инфраструктуры
     * (AuthController, LogoutController и др.).
     */
    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient client = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("test-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }
}