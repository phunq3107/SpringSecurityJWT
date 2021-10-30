package com.phunq.springsecurityjwt.security;

import com.phunq.springsecurityjwt.domain.User;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author phunq3107
 * @since 10/30/2021
 */
@Component
@AllArgsConstructor
public class MyAuthenticationProvider implements AuthenticationProvider {

  private final UserDetailsService userService;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
        = (UsernamePasswordAuthenticationToken) authentication;
    String username = (String) usernamePasswordAuthenticationToken.getPrincipal();
    String rawPassword = (String) usernamePasswordAuthenticationToken.getCredentials();

    User user = (User) userService.loadUserByUsername(username);

    if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
      throw new BadCredentialsException("Bad credentials");
    }
    return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return aClass.equals(UsernamePasswordAuthenticationToken.class);
  }
}
