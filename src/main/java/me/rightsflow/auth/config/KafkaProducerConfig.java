package me.rightsflow.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.serializer.JsonSerializer;

import java.util.HashMap;
import java.util.Map;

/**
 * Конфигурация Kafka producer для rf-auth-svc.
 *
 * <p>Используется только для публикации событий инвалидации кэша прав
 * в топик {@code rf.permissions.invalidated}.</p>
 *
 * <p>Сериализация: JSON (не Avro) — событие маленькое,
 * Schema Registry избыточен для этого случая.</p>
 */
@Slf4j
@Configuration
public class KafkaProducerConfig {

    @Value("${spring.kafka.bootstrap-servers:kafka.micxem:9092}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, Object> permissionProducerFactory() {
        Map<String, Object> props = new HashMap<>();

        props.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        props.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, JsonSerializer.class);

        // Ждём подтверждения от лидера партиции.
        // "all" здесь избыточно для некритичных событий инвалидации кэша.
        props.put(ProducerConfig.ACKS_CONFIG, "1");

        // Повторная отправка при временных сбоях
        props.put(ProducerConfig.RETRIES_CONFIG, 3);
        props.put(ProducerConfig.RETRY_BACKOFF_MS_CONFIG, 1000);

        // Идентификатор в метриках Kafka
        props.put(ProducerConfig.CLIENT_ID_CONFIG, "rf-auth-svc-permission-producer");

        // Отключаем добавление заголовка __TypeId__ в Kafka-сообщения.
        // Консьюмеры (rf-common-lib) могут быть в других модулях и не иметь
        // класса продюсера в своём classpath — они десериализуют по VALUE_DEFAULT_TYPE.
        props.put(JsonSerializer.ADD_TYPE_INFO_HEADERS, false);

        log.info("Kafka producer configured for bootstrap servers: {}", bootstrapServers);
        return new DefaultKafkaProducerFactory<>(props);
    }

    @Bean
    public KafkaTemplate<String, Object> kafkaTemplate(ProducerFactory<String, Object> permissionProducerFactory) {
        return new KafkaTemplate<>(permissionProducerFactory);
    }
}
