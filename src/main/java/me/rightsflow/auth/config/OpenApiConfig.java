package me.rightsflow.auth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Value("${RF_AUTH_SVC_HOSTNAME_EXTERNAL:localhost:8090}")
    private String contractHost;

    @Value("${RF_AUTH_SVC_PROTOCOL_EXTERNAL:http}")
    private String protocol;

    private static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI externalApiOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("RightsFlow Auth — External API")
                        .description("API для внешних клиентов (admin_client): управление SERVICE-пользователями. "
                                + "Получите токен через POST /api/auth/v1/login и укажите его в Authorize (Bearer).")
                        .version("1.0.0")
                        .contact(
                                new Contact()
                                        .name("Developer")
                                        .email("micxem@yandex.ru")
                        )
                )
                .servers(
                        List.of (
                                 new Server()
                                        .url(protocol + "://" + contractHost + "/auth")
                                        .description("Основной адрес микро-сервиса")
                        )
                )
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME))
                .components(new Components()
                        .addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                                .name(BEARER_SCHEME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}
