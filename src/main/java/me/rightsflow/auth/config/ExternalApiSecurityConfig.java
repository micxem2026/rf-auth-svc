package me.rightsflow.auth.config;

import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import me.rightsflow.auth.service.RfAuthUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;

/**
 * Инфраструктура для отдельного REST-эндпоинта логина внешнего API
 * (POST /api/auth/v1/login), не связанного с OAuth2 Authorization Code /
 * Client Credentials flow.
 * <p>
 * JwtEncoder переиспользует тот же {@link com.nimbusds.jose.jwk.source.JWKSource},
 * которым подписываются обычные OAuth2-токены (см. {@link AuthorizationServerConfig#jwkSource()}),
 * поэтому выпущенный здесь JWT проходит стандартную проверку в oauth2ResourceServer().jwt()
 * — как в rf-auth-svc, так и во всех остальных микросервисах платформы.
 */
@Configuration
@RequiredArgsConstructor
public class ExternalApiSecurityConfig {

    @Bean
    public JwtEncoder externalApiJwtEncoder(com.nimbusds.jose.jwk.source.JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * Отдельный AuthenticationManager для /login: username+password → UserDetails,
     * со всеми стандартными проверками статуса аккаунта (enabled/locked/expired)
     * через DaoAuthenticationProvider.
     */
    @Bean
    public AuthenticationManager externalLoginAuthenticationManager(
            RfAuthUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }
}
