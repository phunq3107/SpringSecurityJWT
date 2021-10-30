package com.phunq.springsecurityjwt.service;

import com.phunq.springsecurityjwt.domain.Role;
import com.phunq.springsecurityjwt.domain.User;
import com.phunq.springsecurityjwt.exception.UsernameNotExists;
import java.util.List;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public interface UserService {

  User saveUser(User user);

  Role saveRole(Role role);

  void addRoleToUser(String username, String roleName) throws UsernameNotExists;

  User getUser(String username);

  List<User> getUsers();

}
