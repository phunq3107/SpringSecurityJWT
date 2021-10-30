package com.phunq.springsecurityjwt.security;

import com.google.common.hash.Hashing;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Component
public class MyPasswordEncoder implements PasswordEncoder {

  private final Integer SALT_LENGTH = 32;
  private final String SALTCHARS = "abcdefghijklmnopqrstuvwxyz1234567890";
  private final Random rnd = new Random();

  private String generateSaltString(Integer length) {
    StringBuilder salt = new StringBuilder();
    while (salt.length() < length) {
      int index = (int) (rnd.nextFloat() * SALTCHARS.length());
      salt.append(SALTCHARS.charAt(index));
    }
    return salt.toString();
  }

  private String sha256(String rawPassword) {
    return Hashing.sha256().hashString(rawPassword, StandardCharsets.UTF_8).toString();
  }


  @Override
  public String encode(CharSequence rawPassword) {
    String saltString = generateSaltString(SALT_LENGTH);
    return saltString + sha256(saltString + rawPassword);
  }

  @Override
  public boolean matches(CharSequence rawPassword, String encodedPassword) {
    String salt = encodedPassword.substring(0, SALT_LENGTH);
    String encodeRawPassword = salt + sha256(salt + rawPassword);
    return encodeRawPassword.equals(encodedPassword);
  }
}
