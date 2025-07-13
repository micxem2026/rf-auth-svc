package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.OAuth2RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2RegisteredClientRepository extends JpaRepository<OAuth2RegisteredClientEntity, String> {

    Optional<OAuth2RegisteredClientEntity> findByClientId(String clientId);

    boolean existsByClientId(String clientId);

    List<OAuth2RegisteredClientEntity> findByCreatedBy(String createdBy);

    @Query("SELECT c FROM OAuth2RegisteredClientEntity c WHERE c.createdBy != 'system' ORDER BY c.createdAt DESC")
    List<OAuth2RegisteredClientEntity> findUserCreatedClients();

    @Query("SELECT c FROM OAuth2RegisteredClientEntity c WHERE c.createdBy = 'system'")
    List<OAuth2RegisteredClientEntity> findSystemClients();
}

