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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

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
                        "/userinfo")
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

}

