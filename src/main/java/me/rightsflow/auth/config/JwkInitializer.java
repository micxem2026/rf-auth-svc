package me.rightsflow.auth.config;

import me.rightsflow.auth.service.JwkService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
@Profile("!test") // Не активен в тестовом профиле
public class JwkInitializer implements CommandLineRunner {

    private final JwkService jwkService;

    /**
     * Executes the initialization of JWK keys when the application starts.
     * This method is invoked automatically as part of the Spring Boot
     * application startup process and ensures that the JWK keys are
     * properly initialized and available for use.
     *
     * @param args Command line arguments.
     * @throws Exception if an error occurs during key initialization.
     */
    @Override
    public void run(String... args) throws Exception {
           jwkService.initializeKeys();
    }
}
