package me.rightsflow.auth.listener;

import me.rightsflow.auth.entity.UserEntity;
import me.rightsflow.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
public class SecurityEventListener {

    private static final Logger securityLogger = LoggerFactory.getLogger("SECURITY");

    @Autowired
    UserRepository userRepository;

    @EventListener
    @Transactional
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String principal = event.getAuthentication().getName();
        String details = event.getAuthentication().getDetails() != null ?
                event.getAuthentication().getDetails().toString() : "N/A";

        UserEntity user = userRepository.findByUsername(principal)
                .orElse(null);
        if (user != null) {
            user.setLastLogon(LocalDateTime.now());
            userRepository.save(user);
        }

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