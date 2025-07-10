package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.JwkEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface JwkRepository extends JpaRepository<JwkEntity, String> {

    /**
     * Returns a list of JwkEntity objects representing the active JWKS, sorted by descending creation date.
     * The JWKS are considered active if their expiration date is greater than the provided date and time.
     * @param now the current date and time
     * @return a list of JwkEntity objects
     */
    @Query("SELECT j FROM JwkEntity j WHERE j.expirationDate > :now ORDER BY j.createdAt DESC")
    List<JwkEntity> findActiveKeys(LocalDateTime now);

    /**
     * Returns an Optional containing the latest active JWKS if one is available, or an empty Optional otherwise.
     * The JWKS are considered active if their expiration date is greater than the provided date and time.
     * @param now the current date and time
     * @return an Optional containing the latest active JWKS
     */
    @Query("SELECT j FROM JwkEntity j WHERE j.expirationDate > :now ORDER BY j.createdAt DESC LIMIT 1")
    Optional<JwkEntity> findLatestActiveKey(LocalDateTime now);

    /**
     * Returns a list of JwkEntity objects representing the expired JWKS, sorted by descending creation date.
     * The JWKS are considered expired if their expiration date is less than or equal to the provided date and time.
     * @param now the current date and time
     * @return a list of JwkEntity objects
     */
    @Query("SELECT j FROM JwkEntity j WHERE j.expirationDate <= :now")
    List<JwkEntity> findExpiredKeys(LocalDateTime now);

    /**
     * Deletes all JwkEntity objects whose expiration date is before the provided date and time.
     * @param dateTime the date and time before which JWKS should be deleted
     */
    void deleteByExpirationDateBefore(LocalDateTime dateTime);
}
