package me.rightsflow.auth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.rightsflow.auth.service.JwkService;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.net.PasswordAuthentication;
import java.time.Duration;
import java.util.UUID;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    @Value("${RF_AUTH_SVC_HOSTNAME:${hostname:localhost}}")
    private String issuerHost;

    @Value("${server.port:9000}")
    private Integer issuerPort;

    @Value("${rightsflow.oauth.token.default-ttl-seconds:3600}")
    private long defTokenTtl;

    @Value("${rightsflow.oauth.token.refresh-ttl-days:30}")
    private long refreshTokenTtl;

    private final JwkService jwkService;
    private final RfAuthUserDetailsService userDetailsService;


    /**
     * SecurityFilterChain with high priority (1) for Authorization Server.
     *
     * This filter chain is applied to the following URL paths:
     * <ul>
     * <li>/oauth2/**</li>
     * <li>/connect/**</li>
     * <li>/.well-known/jwks.json</li>
     * <li>/.well-known/openid-configuration</li>
     * </ul>
     *
     * It uses standard configuration for Authorization Server with OIDC.
     *
     * @param http HttpSecurity object for configuration.
     * @return Configured SecurityFilterChain.
     * @throws Exception If an error occurs during configuration.
     */
    @Bean
    @Order(1) // Высокий приоритет для фильтров Authorization Server
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Применяем стандартную конфигурацию сервера авторизации
        http.with(OAuth2AuthorizationServerConfigurer.authorizationServer(), Customizer.withDefaults());

        // Настраиваем OIDC, если это нужно сделать отдельно (часто Customizer.withDefaults() уже достаточно)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());

        // Определяем, какие URL-пути должна обрабатывать эта цепочка
        http
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
     * Конфигурация цепочки фильтров безопасности для обычных запросов.
     * Обрабатывает запросы к login, error, actuator, api и userinfo.
     * <p>
     * Для /actuator/**, /error, /login - доступ без аутентификации.
     * Для /api/**, /userinfo - доступ только для аутентифицированных пользователей.
     * <p>
     * Используется OAuth2ResourceServerConfigurer для конфигурации сервера ресурсов.
     * <p>
     * FormLoginConfigurer настраивается для обычной формы аутентификации.
     * LogoutConfigurer настраивается для logout.
     * ExceptionHandlingConfigurer настраивается для обработки ошибок.
     *
     * @param http Объект HttpSecurity для настройки безопасности.
     * @return Цепочка фильтров безопасности.
     * @throws Exception Если возникает ошибка при настройке.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(
                        "/",
                        "/login",
                        "/logout",
                        "/error",
                        "/actuator/**",
                        "/api/**",
                        "/userinfo")
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                )
                .authorizeHttpRequests(authorize -> authorize
                          .requestMatchers("/actuator/**",
                                           "/error",
                                           "/login",
                                           "/logout",
                                           "/").permitAll()
                          .requestMatchers("/api/**",
                                           "/userinfo").authenticated()
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
/*                        .logoutRequestMatcher(request ->
                                "/logout".equals(request.getServletPath()) &&
                                        ("GET".equals(request.getMethod()) || "POST".equals(request.getMethod()))
                        )*/
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
                .csrf(Customizer.withDefaults())
                //.csrf(AbstractHttpConfigurer::disable)
                .userDetailsService(userDetailsService);

        return http.build();
    }


    /**
     * Регистрирует два клиента:
     *  1. "svc-client" - для Client Credentials Grant
     *  2. "spa-client" - для Authorization Code Flow
     *
     * @return Repository of registered clients.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
        //log.debug("PASSWORD: {}", passwordEncoder.encode(""));
        RegisteredClient svcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("svc-client")
                .clientSecret("$2a$10$PF4SCvOpUMba.p2Mx2bL/e/3ldyZMq70.VgO.bq.DtjoTx8PFj5j.")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .scope("update")
                .scope("execute")
                .scope("delete")
                .scope("create")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(defTokenTtl))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();


        RegisteredClient spaClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("spa-client")
                .clientSecret("$2a$10$K9CrnOBK41aJMDFMMc.teeVpq1tg1IclkyCOUKvlOzKey1XPUVV0m")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://%s:%d/callback".formatted(issuerHost, issuerPort))
                .redirectUri("http://localhost:%d/callback".formatted(issuerPort))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                .scope("update")
                .scope("execute")
                .scope("delete")
                .scope("create")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(defTokenTtl))
                        .refreshTokenTimeToLive(Duration.ofDays(refreshTokenTtl))
                        .reuseRefreshTokens(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(svcClient, spaClient);
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
     * Creates a JwtDecoder bean that is responsible for decoding JWT tokens
     * using the provided JWKSource.
     *
     * @param jwkSource The JWK source used to load JSON Web Keys.
     * @return A JwtDecoder configured with the provided JWKSource.
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
                .issuer("http://%s:%d".formatted(issuerHost, issuerPort))
                .build();
    }

    /**
     * Настраивает JWT токен, добавляя в него дополнительные claims.
     * Включает роли, display_name и email пользователя.
     *
     * @return OAuth2TokenCustomizer для настройки JWT.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return new RfAuthJwtTokenCustomizer();
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
