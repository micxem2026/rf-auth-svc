package me.rightsflow.auth.jackson;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.io.IOException;
import java.time.Duration;

public class TokenSettingsDeserializer extends JsonDeserializer<TokenSettings> {

    @Override
    public TokenSettings deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);

        TokenSettings.Builder builder = TokenSettings.builder();

        JsonNode settingsNode = node.get("settings");
        if (settingsNode != null && settingsNode.isObject()) {
            if (settingsNode.has("settings.token.reuse-refresh-tokens")) {
                builder.reuseRefreshTokens(settingsNode.get("settings.token.reuse-refresh-tokens").asBoolean());
            }
            if (settingsNode.has("settings.token.access-token-time-to-live")) {
                JsonNode durationNode = settingsNode.get("settings.token.access-token-time-to-live");
                if (durationNode.isArray() && durationNode.size() == 2) {
                    double seconds = durationNode.get(1).asDouble();
                    builder.accessTokenTimeToLive(Duration.ofSeconds((long) seconds));
                }
            }
            if (settingsNode.has("settings.token.refresh-token-time-to-live")) {
                JsonNode durationNode = settingsNode.get("settings.token.refresh-token-time-to-live");
                if (durationNode.isArray() && durationNode.size() == 2) {
                    double seconds = durationNode.get(1).asDouble();
                    builder.refreshTokenTimeToLive(Duration.ofSeconds((long) seconds));
                }
            }
            if (settingsNode.has("settings.token.access-token-format")) {
                JsonNode formatNode = settingsNode.get("settings.token.access-token-format");
                if (formatNode.has("value")) {
                    String formatValue = formatNode.get("value").asText();
                    if ("self-contained".equals(formatValue)) {
                        builder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
                    } else {
                        builder.accessTokenFormat(OAuth2TokenFormat.REFERENCE);
                    }
                }
            }
        }

        return builder.build();
    }
}