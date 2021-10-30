package com.phunq.springsecurityjwt.repository;

import com.phunq.springsecurityjwt.domain.Role;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public interface RoleRepo extends JpaRepository<Role, String> {

  Optional<Role> findByName(String name);

}
