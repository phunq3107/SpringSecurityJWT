package com.phunq.springsecurityjwt.domain;

import javax.persistence.Entity;
import javax.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author phunq3107
 * @since 10/29/2021
 */
@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Role implements GrantedAuthority {

  @Id
  private String name;

  @Override
  public String getAuthority() {
    return this.name;
  }
}
