package com.phunq.springsecurityjwt.repository;

import com.phunq.springsecurityjwt.domain.User;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public interface UserRepo extends JpaRepository<User, UUID> {

  Optional<User> findByUsername(String username);

}
