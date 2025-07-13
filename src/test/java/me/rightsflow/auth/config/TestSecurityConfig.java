package me.rightsflow.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.rightsflow.auth.repository.JwkRepository;
import me.rightsflow.auth.repository.RoleRepository;
import me.rightsflow.auth.repository.UserRepository;
import me.rightsflow.auth.service.JwkService;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Duration;
import java.util.UUID;

@TestConfiguration
@EnableWebSecurity
@Profile("test")
public class TestSecurityConfig {

    // Mock beans для репозиториев
    @MockitoBean
    private JwkRepository jwkRepository;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private RoleRepository roleRepository;

    // Mock beans для сервисов
    @MockitoBean
    private RfAuthUserDetailsService userDetailsService;

    @Bean
    @Primary
    public JwkService mockJwkService() {
        return org.mockito.Mockito.mock(JwkService.class);
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean
    @Primary
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(
                        "/",
                        "/login",
                        "/logout",
                        "/error",
                        "/actuator/**",
                        "/api/**",
                        "/userinfo",
                        "/admin/**")
                .authorizeHttpRequests(authorize -> authorize
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
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    @Primary
    public PasswordEncoder testPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return new RfAuthLogoutSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new RfAuthAuthenticationFailureHandler();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new RfAuthAuthenticationSuccessHandler();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

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
                        .accessTokenTimeToLive(Duration.ofSeconds(3600))
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
                .redirectUri("http://%s:%d/callback".formatted("localhost", 9000))
                .redirectUri("http://localhost:%d/callback".formatted(9000))
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
                        .accessTokenTimeToLive(Duration.ofSeconds(3600))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .reuseRefreshTokens(true)
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(svcClient, spaClient);

    }

}

