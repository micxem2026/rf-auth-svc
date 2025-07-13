package me.rightsflow.auth.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.IOException;

public class ClientSettingsDeserializer extends JsonDeserializer<ClientSettings> {

    @Override
    public ClientSettings deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);

        ClientSettings.Builder builder = ClientSettings.builder();

        JsonNode settingsNode = node.get("settings");
        if (settingsNode != null && settingsNode.isObject()) {
            if (settingsNode.has("settings.client.require-proof-key")) {
                builder.requireProofKey(settingsNode.get("settings.client.require-proof-key").asBoolean());
            }
            if (settingsNode.has("settings.client.require-authorization-consent")) {
                builder.requireAuthorizationConsent(settingsNode.get("settings.client.require-authorization-consent").asBoolean());
            }
        }

        return builder.build();
    }
}