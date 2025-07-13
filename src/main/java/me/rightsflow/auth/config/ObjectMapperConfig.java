package me.rightsflow.auth.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import me.rightsflow.auth.jackson.ClientSettingsDeserializer;
import me.rightsflow.auth.jackson.TokenSettingsDeserializer;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.List;

@Configuration
public class ObjectMapperConfig {

    /**
     * Стандартный ObjectMapper для использования в веб-слое (контроллеры).
     * Он не содержит специфичных для Spring Security модулей.
     * @return Стандартный ObjectMapper.
     */
    @Bean
    @Primary // Помечаем как основной, чтобы Spring MVC использовал его по умолчанию
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule()); // Достаточно поддержки дат
        // Отключаем запись дат в виде timestamp (массива), вместо этого будет строка ISO-8601
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    /**
     * Специализированный ObjectMapper для (де)сериализации данных Spring Security.
     * Он будет использоваться только в JPA-репозитории.
     * @return ObjectMapper с модулями Spring Security.
     */
    @Bean
    @Qualifier("securityObjectMapper")
    public ObjectMapper securityObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());

        ClassLoader classLoader = getClass().getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        mapper.registerModules(securityModules);

        // Создаем кастомный модуль для наших классов
        SimpleModule customModule = new SimpleModule();
        customModule.addDeserializer(ClientSettings.class, new ClientSettingsDeserializer());
        customModule.addDeserializer(TokenSettings.class, new TokenSettingsDeserializer());
        mapper.registerModule(customModule);

        return mapper;
    }

}
