package com.phunq.springsecurityjwt;

import com.phunq.springsecurityjwt.domain.Role;
import com.phunq.springsecurityjwt.domain.User;
import com.phunq.springsecurityjwt.service.UserService;
import java.util.ArrayList;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@SpringBootApplication
public class SpringSecurityJwtApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityJwtApplication.class, args);
  }

  @Bean
  CommandLineRunner run(UserService userService) {
    return args -> {
      userService.saveRole(new Role("ROLE_USER"));
      userService.saveRole(new Role("ROLE_MANAGER"));
      userService.saveRole(new Role("ROLE_ADMIN"));
      userService.saveRole(new Role("ROLE_SUPER_ADMIN"));

      userService.saveUser(
          new User(null, "Phu User", "user", "123", new ArrayList<>())
      );
      userService.saveUser(
          new User(null, "Phu Manager", "manager", "123", new ArrayList<>())
      );
      userService.saveUser(
          new User(null, "Phu Admin", "admin", "123", new ArrayList<>())
      );
      userService.saveUser(
          new User(null, "Phu Super Admin", "sadmin", "123", new ArrayList<>())
      );

      userService.addRoleToUser("user", "ROLE_USER");
      userService.addRoleToUser("admin", "ROLE_ADMIN");
      userService.addRoleToUser("manager", "ROLE_MANAGER");
      userService.addRoleToUser("sadmin", "ROLE_SUPER_ADMIN");

    };
  }

}
