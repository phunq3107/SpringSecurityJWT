package com.phunq.springsecurityjwt.exception;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
public class RoleNameNotExists extends Exception{

  private final String roleName;

  public RoleNameNotExists(String roleName) {
    this.roleName = roleName;
  }

  @Override
  public String getMessage() {
    return String.format("Role name (%s) not exists", this.roleName);
  }

}
