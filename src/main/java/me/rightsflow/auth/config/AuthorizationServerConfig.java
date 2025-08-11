package me.rightsflow.auth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.repository.OAuth2RegisteredClientRepository;
import me.rightsflow.auth.service.JpaRegisteredClientRepository;
import me.rightsflow.auth.service.JwkService;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    @Value("${RF_AUTH_SVC_HOSTNAME:${hostname:localhost}}")
    private String issuerHost;

    @Value("${server.port:9000}")
    private Integer issuerPort;

    private final JwkService jwkService;
    private final RfAuthUserDetailsService userDetailsService;
    private final JpaRegisteredClientRepository jpaRegisteredClientRepository;

    /**
     * Bean SecurityFilterChain, отвечающий за безопасность
     * конечных точек сервера авторизации.
     * <p>
     * Он применяет стандартную конфигурацию сервера авторизации OAuth2
     * и конфигурацию OIDC.
     * <p>
     * Он также настраивает security matcher для обработки только связанных с OAuth2 конечных точек
     * и настраивает обработку исключений для перенаправления неавторизованных запросов на страницу входа.
     * <p>
     * Фильтр цепочки имеет наивысший приоритет (1), чтобы обеспечить его выполнение до любых других фильтров цепочек.
     *
     * @param http Объект HttpSecurity, используемый для создания цепочки безопасности.
     * @return Созданный bean цепочки безопасности.
     * @throws Exception Если происходит ошибка при создании цепочки безопасности.
     */
    @Bean
    @Order(1) // Высокий приоритет для фильтров Authorization Server
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Применяем стандартную конфигурацию сервера авторизации
        http.with(OAuth2AuthorizationServerConfigurer.authorizationServer(), Customizer.withDefaults());

        // Настраиваем OIDC, если это нужно сделать отдельно
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc((oidc) ->
                        oidc.clientRegistrationEndpoint(Customizer.withDefaults())
                );

        // Определяем, какие URL-пути должна обрабатывать эта цепочка
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .securityMatcher(
                        "/oauth2/**",
                        "/connect/**",
                        "/.well-known/jwks.json",
                        "/.well-known/openid-configuration",
                        "/.well-known/base64encode"
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }


    /**
     * Настройка стандартной цепочки безопасности для обработки веб-безопасности.
     * <p>
     * Применяет security matcher для указанных endpoint'ов, таких как корневой, login, logout,
     * страницы ошибок, actuator, API, user info, и admin.
     * <p>
     * Настройка сервера ресурсов OAuth2 с валидацией токенов JWT и настройка правил авторизации:
     * позволяет доступ к actuator, error, login, и logout; требует аутентификации для API и user info;
     * и ограничивает доступ к admin только для пользователей с ролью ADMIN.
     * <p>
     * Настройка форменной аутентификации с кастомными обработчиками успеха и неудачи, а также настройка logout
     * с кастомным обработчиком успеха, инвалидацией сессии и удалением cookie.
     * <p>
     * Обработка исключений путем перенаправления на кастомную страницу доступа запрещен и неавторизованных обработчиков.
     * <p>
     * Включение защиты от CSRF и использование кастомного сервиса user details.
     *
     * @param http The HttpSecurity object used to build the security filter chain.
     * @return The built security filter chain bean.
     * @throws Exception If there is an error when building the security filter chain.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .securityMatcher(
                        "/",
                        "/login",
                        "/logout",
                        "/error",
                        "/actuator/**",
                        "/api/**",
                        "/userinfo",
                        "/admin/**")
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                )
                .authorizeHttpRequests(authorize -> authorize
                        //.dispatcherTypeMatchers(DispatcherType.FORWARD, DispatcherType.ERROR).permitAll()
                        .requestMatchers("/actuator/**",
                                "/error",
                                "/login",
                                "/logout",
                                "/").permitAll()
                        .requestMatchers("/api/**",
                                "/userinfo").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(authenticationSuccessHandler())
                        .failureHandler(authenticationFailureHandler())
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .clearAuthentication(true)
                        .permitAll()
                )
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedPage("/error?type=access-denied")
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendRedirect("/error?type=unauthorized");
                        })
                )
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers("/oauth2/**", "/connect/**", "/.well-known/**")
                )
                //.csrf(AbstractHttpConfigurer::disable)
                .userDetailsService(userDetailsService);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Разрешенные источники (origins)
        configuration.setAllowedOriginPatterns(List.of(
                "*"
        ));

        // Разрешенные методы
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"
        ));

        // Разрешенные заголовки
        configuration.setAllowedHeaders(List.of(
                "*"
        ));

        // Разрешить отправку cookies и авторизационных заголовков
        configuration.setAllowCredentials(true);

        // Заголовки, которые клиент может читать
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization", "Cache-Control", "Content-Type"
        ));

        // Время кэширования preflight запроса
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Возвращает репозиторий на основе JPA для сущностей {@link RegisteredClient}
     * вместо стандартной реализации InMemory.
     * <p>
     * Это необходимо для хранения и извлечения зарегистрированных клиентов из базы данных.
     * <p>
     * Возвращаемый репозиторий является экземпляром {@link JpaRegisteredClientRepository}.
     *
     * @return JPA-based репозиторий для зарегистрированных клиентов.
     */
    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepository() {
        // Возвращаем JPA-based репозиторий вместо InMemory
        return jpaRegisteredClientRepository;
    }

    /**
     * Создает и возвращает JWKSource, который предоставляет JWK для подписи токенов.
     * Ключи загружаются из базы данных и управляются ротацией.
     *
     * @return JWKSource.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        return new RfAuthJWKSource(jwkService);
    }

    /**
     * Создает бин JwtDecoder, который отвечает за декодирование токенов JWT
     * с использованием предоставленного JWKSource.
     *
     * @param jwkSource Источник JWK, используемый для загрузки JSON-ключей.
     * @return JwtDecoder, сконфигурированный с помощью предоставленного JWKSource.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Настройки Authorization Server (например, URI издателя).
     *
     * @return AuthorizationServerSettings.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        log.debug("ISSUER: {}:{}", issuerHost, issuerPort);
        return AuthorizationServerSettings.builder()
                .issuer("http://%s:%d/auth".formatted(issuerHost, issuerPort))
                .build();
    }

    /**
     * Настраивает JWT токен, добавляя в него дополнительные claims.
     * Включает роли, display_name и email пользователя.
     *
     * @return OAuth2TokenCustomizer для настройки JWT.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(OAuth2RegisteredClientRepository repo) {
        return new RfAuthJwtTokenCustomizer(repo);
    }

    /**
     * Кодировщик паролей BCrypt.
     *
     * @return PasswordEncoder.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Bean, возвращающий AuthenticationSuccessHandler, обрабатывающий
     * успешную аутентификацию.
     * <p>
     * По умолчанию, он перенаправляет на URL,
     * найденный в сессии, или на "/". Если в сессии есть параметры OAuth2,
     * он перенаправляет на authorization endpoint.
     *
     * @return AuthenticationSuccessHandler.
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new RfAuthAuthenticationSuccessHandler();
    }

    /**
     * AuthenticationFailureHandler, который обрабатывает события неудачной аутентификации.
     * Он перенаправляет на "/error?type=unauthorized" со статусом 401.
     *
     * @return AuthenticationFailureHandler.
     */
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new RfAuthAuthenticationFailureHandler();
    }

    /**
     * LogoutSuccessHandler, обрабатывающий событие успешного logout.
     * Он перенаправляет на "/login?logout=true" со статусом 200.
     *
     * @return LogoutSuccessHandler.
     */
    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new RfAuthLogoutSuccessHandler();
    }

}
