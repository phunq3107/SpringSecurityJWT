package com.phunq.springsecurityjwt.exception;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public class UsernameNotExists extends Exception {

  private final String username;

  public UsernameNotExists(String username) {
    this.username = username;
  }

  @Override
  public String getMessage() {
    return String.format("Username (%s) not exists", this.username);
  }

}
