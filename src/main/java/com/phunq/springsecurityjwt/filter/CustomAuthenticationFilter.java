package com.phunq.springsecurityjwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phunq.springsecurityjwt.domain.User;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;
  private final Long TOKEN_TIME = 10 * 60 * 1000L;
  private final Long REFRESH_TOKEN_TIME = 30 * 60 * 1000L;

  public CustomAuthenticationFilter(
      AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    log.info("Username: {}, password: {}", username, password);
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(username, password);
    return authenticationManager.authenticate(authenticationToken);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException {
    User user = (User) authResult.getPrincipal();
    String accessToken = JwtUtils.generateAccessToken(user, request.getRequestURL().toString());
    String refreshToken = JwtUtils.generateRefreshToken(user, request.getRequestURL().toString());
    Map<String, String> tokens = new HashMap<>() {{
      put("access_token", accessToken);
      put("refresh_token", refreshToken);
    }};
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    new ObjectMapper().writeValue(response.getOutputStream(), tokens);
  }
}
