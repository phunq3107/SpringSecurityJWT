package com.phunq.springsecurityjwt.api;

import com.phunq.springsecurityjwt.domain.Role;
import com.phunq.springsecurityjwt.domain.User;
import com.phunq.springsecurityjwt.exception.UsernameNotExists;
import com.phunq.springsecurityjwt.service.UserService;
import java.net.URI;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@RestController
@RequestMapping({"/api"})
@AllArgsConstructor
public class UserResource {

  private final UserService userService;

  @GetMapping({"/users"})
  public ResponseEntity<List<User>> getUsers() {
    return ResponseEntity.ok().body(userService.getUsers());
  }

  @PostMapping({"/users"})
  public ResponseEntity<User> saveUser(@RequestBody User user) {
    URI uri = URI.create(
        ServletUriComponentsBuilder
            .fromCurrentContextPath()
            .path("/api/users").toUriString()
    );
    return ResponseEntity.created(uri).body(userService.saveUser(user));
  }

  @PostMapping({"/roles"})
  public ResponseEntity<Role> saveRole(@RequestBody Role role) {
    URI uri = URI.create(
        ServletUriComponentsBuilder
            .fromCurrentContextPath()
            .path("/api/roles").toUriString()
    );
    return ResponseEntity.created(uri).body(userService.saveRole(role));
  }

  @PostMapping({"/roles/addToUser"})
  public ResponseEntity<?> saveRole(@RequestBody RoleToUserForm form) throws UsernameNotExists {
    userService.addRoleToUser(form.getUsername(), form.getRoleName());
    return ResponseEntity.ok().build();
  }

}

@Data
class RoleToUserForm {

  private String username;
  private String roleName;

}
