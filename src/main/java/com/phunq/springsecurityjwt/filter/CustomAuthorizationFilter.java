package com.phunq.springsecurityjwt.filter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phunq.springsecurityjwt.domain.Role;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().equals("/api/login")
        || request.getServletPath().equals("/api/token/refresh")) {
      filterChain.doFilter(request, response);
    } else {
      String authorizationHeader = request.getHeader(AUTHORIZATION);
      if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        try {
          String token = authorizationHeader.substring("Bearer ".length());
          log.info("Token: {}", token);
          Algorithm algorithm = JwtUtils.getAlgorithm();
          JWTVerifier verifier = JWT.require(algorithm).build();
          DecodedJWT decodedJWT = verifier.verify(token);
          String username = decodedJWT.getSubject();
          String[] roles =
              decodedJWT.getClaim("role").asArray(String.class);
          Collection<Role> authorities =
              Arrays.stream(roles).map(Role::new).collect(Collectors.toList());
          UsernamePasswordAuthenticationToken authenticationToken =
              new UsernamePasswordAuthenticationToken(username, null, authorities);
          SecurityContextHolder.getContext().setAuthentication(authenticationToken);
          filterChain.doFilter(request, response);
        } catch (Exception e) {
          log.error("Error logging in: {}", e.getMessage());
          response.setHeader("error", e.getMessage());
          response.setStatus(FORBIDDEN.value());
          response.setContentType(APPLICATION_JSON_VALUE);
          Map<String, String> error = new HashMap<>() {{
            put("error_message", e.getMessage());
          }};
          new ObjectMapper().writeValue(response.getOutputStream(), error);

        }
      } else {
        filterChain.doFilter(request, response);
      }

    }
  }
}
