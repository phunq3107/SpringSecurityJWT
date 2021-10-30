package com.phunq.springsecurityjwt.filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.phunq.springsecurityjwt.domain.User;
import java.util.Date;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public class JwtUtils {

  private static final String SECRET_KEY = "97e6061b1fb64cce76d2e7cd9adc6733";
  private static final Long TOKEN_TIME = 10 * 60 * 1000L;//10 minutes
  private static final Long REFRESH_TOKEN_TIME = 30 * 60 * 1000L;//30 minutes

  public static Algorithm getAlgorithm() {
    return Algorithm.HMAC256(SECRET_KEY.getBytes());
  }

  public static String generateAccessToken(final User user, String url) {
    return JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_TIME))
        .withIssuer(url)
        .withClaim("role", user.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority).collect(Collectors.toList())
        )
        .sign(getAlgorithm());
  }

  public static String generateRefreshToken(final User user, String url) {
    return JWT.create()
        .withSubject(user.getUsername())
        .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_TOKEN_TIME))
        .withIssuer(url)
        .sign(getAlgorithm());
  }

}
