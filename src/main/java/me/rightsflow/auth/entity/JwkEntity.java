package me.rightsflow.auth.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "jwks")
@Data
public class JwkEntity {

    @Id
    private UUID kid;

    @Column(name = "jwk_set", nullable = false, columnDefinition = "TEXT")
    private String jwkSet;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "expiration_date", nullable = false)
    private LocalDateTime expirationDate;
}