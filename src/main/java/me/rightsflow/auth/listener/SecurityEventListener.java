package me.rightsflow.auth.listener;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class SecurityEventListener {

    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String principal = event.getAuthentication().getName();
        String details = event.getAuthentication().getDetails() != null ?
                event.getAuthentication().getDetails().toString() : "N/A";

        if (event.getAuthentication() instanceof OAuth2ClientAuthenticationToken) {
            securityLogger.info("OAuth2 Client Authentication Success - Client: {}, Details: {}",
                    principal, details);
        } else {
            securityLogger.info("User Authentication Success - User: {}, Details: {}",
                    principal, details);
        }
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String principal = event.getAuthentication().getName();
        String details = event.getAuthentication().getDetails() != null ?
                event.getAuthentication().getDetails().toString() : "N/A";

        securityLogger.warn("Authentication Failure - Principal: {}, Details: {}, Exception: {}",
                principal, details, event.getException().getMessage());
    }
}