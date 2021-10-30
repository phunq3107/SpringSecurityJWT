package com.phunq.springsecurityjwt.service;

import com.phunq.springsecurityjwt.domain.Role;
import com.phunq.springsecurityjwt.domain.User;
import com.phunq.springsecurityjwt.exception.RoleNameNotExists;
import com.phunq.springsecurityjwt.exception.UsernameNotExists;
import com.phunq.springsecurityjwt.repository.RoleRepo;
import com.phunq.springsecurityjwt.repository.UserRepo;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Service
@Transactional
@Slf4j
@AllArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

  private final UserRepo userRepo;
  private final RoleRepo roleRepo;
  private final PasswordEncoder passwordEncoder;

  @Override
  public User saveUser(User user) {
    log.info("Saving new user {} to database", user.getName());
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    return userRepo.save(user);
  }

  @Override
  public Role saveRole(Role role) {
    log.info("Saving new role {} to database", role.getName());
    return roleRepo.save(role);
  }

  @SneakyThrows
  @Override
  public void addRoleToUser(String username, String roleName) {
    log.info("Adding role {} to user {}", roleName, username);
    User user = userRepo
        .findByUsername(username)
        .orElseThrow(() -> new UsernameNotExists(username));
    Role role = roleRepo
        .findByName(roleName)
        .orElseThrow(() -> new RoleNameNotExists(roleName));
    user.getRoles().add(role);
  }

  @SneakyThrows
  @Override
  public User getUser(String username) {
    log.info("Fetching user {}", username);
    return userRepo
        .findByUsername(username)
        .orElseThrow(() -> new UsernameNotExists(username));
  }

  @Override
  public List<User> getUsers() {
    log.info("Fetching all users");
    return userRepo.findAll();
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return getUser(username);
  }
}
