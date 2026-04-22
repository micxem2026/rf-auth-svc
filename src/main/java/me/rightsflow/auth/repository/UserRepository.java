package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    /**
     * Find a user by its username.
     * @param username Username of the user.
     * @return An optional containing the user if found, empty otherwise.
     */
    Optional<UserEntity> findByUsername(String username);

    /**
     * Find a user by its email.
     * @param email Email of the user.
     * @return An optional containing the user if found, empty otherwise.
     */
    Optional<UserEntity> findByEmail(String email);

    /**
     * Find a user by its username, with its roles.
     * @param username Username of the user.
     * @return An optional containing the user and its roles if found, empty otherwise.
     */
    @Query("SELECT u FROM UserEntity u LEFT JOIN FETCH u.roles WHERE u.username = :username")
    Optional<UserEntity> findByUsernameWithRoles(String username);

    /**
     * Check if a user with the given username exists.
     * @param username Username of the user.
     * @return true if the user exists, false otherwise.
     */
    boolean existsByUsername(String username);

    /**
     * Check if a user with the given email exists.
     * @param email Email of the user.
     * @return true if the user exists, false otherwise.
     */
    boolean existsByEmail(String email);
}
