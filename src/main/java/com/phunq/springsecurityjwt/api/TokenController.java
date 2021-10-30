package com.phunq.springsecurityjwt.api;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phunq.springsecurityjwt.domain.User;
import com.phunq.springsecurityjwt.filter.JwtUtils;
import com.phunq.springsecurityjwt.service.UserService;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author phunq3107
 * @since 10/30/2021
 */
@RestController
@RequestMapping("/api")
@AllArgsConstructor
public class TokenController {

  private final UserService userService;

  @GetMapping({"/token/refresh"})
  public void refreshToken(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String authorizationHeader = request.getHeader(AUTHORIZATION);
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      try {
        String refreshToken = authorizationHeader.substring("Bearer ".length());
        Algorithm algorithm = JwtUtils.getAlgorithm();
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);
        String username = decodedJWT.getSubject();
        User user = userService.getUser(username);

        String accessToken = JwtUtils.generateAccessToken(user, request.getRequestURL().toString());
        Map<String, String> tokens = new HashMap<>() {{
          put("access_token", accessToken);
          put("refresh_token", refreshToken);
        }};
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
      } catch (Exception e) {
        response.setHeader("error", e.getMessage());
        response.setStatus(FORBIDDEN.value());
        response.setContentType(APPLICATION_JSON_VALUE);
        Map<String, String> error = new HashMap<>() {{
          put("error_message", e.getMessage());
        }};
        new ObjectMapper().writeValue(response.getOutputStream(), error);

      }
    } else {
      throw new RuntimeException("Refresh token is missing");
    }
  }

}
