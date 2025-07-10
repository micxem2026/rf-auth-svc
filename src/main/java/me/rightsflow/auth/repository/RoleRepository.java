package me.rightsflow.auth.repository;

import me.rightsflow.auth.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
    /**
     * Retrieve a role by its name.
     *
     * @param name Role name
     * @return an Optional containing the found RoleEntity, or an empty Optional if no role is found
     */
    Optional<RoleEntity> findByName(String name);

    /**
     * Check if a role with the given name exists.
     *
     * @param name Role name
     * @return true if the role exists, false otherwise
     */
    boolean existsByName(String name);
}
